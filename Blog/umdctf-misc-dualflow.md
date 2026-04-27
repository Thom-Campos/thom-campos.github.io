**Flag:** `UMDCTF{a_little_gram_schmidt_never_hurt_anybody}`

**Categoría:** Misc

**Autor del Reto:** segal

***

## Desafío: dualflow

Este reto de IA tuvo muchas matemáticas. Básicamente había que engañar a un detector de anomalías para que aceptara nuestra data adulterada.

```"my trading model has two flows now! double the flows means double the robustness right?" nc challs.umdctf.io 30303```

Nos pasaron varios archivos para levantar el entorno local: la arquitectura de la red (`flow.py`), los pesos de dos modelos preentrenados, un input de prueba y la lógica de validación del server.

### ¿Qué hace exactamente el sistema?

El sistema usa Normalizing Flows (RealNVP). Para no enredarnos con las fórmulas, imagínense que es una red neuronal que toma datos complejos y los transforma en una distribución predecible.

El servidor usa dos de estos modelos en paralelo como guardias de seguridad. Para lograr el bypass, nuestro payload tenía que cumplir tres condiciones matemáticas súper estrictas al mismo tiempo.

En resumen: la data adulterada tenía que verse más "normal" para el segundo modelo que para el primero, tener una altísima probabilidad de ser real, y mantener su coherencia interna.

### La vulnerabilidad: Ensayo y error

Como teníamos acceso a los pesos de los modelos (un ataque adversario de caja blanca de manual), podíamos calcular exactamente cómo alterar el input original inyectándole un ruido mínimo.

Acá fue donde estuve dando pelea un buen rato. Primero intenté usar un optimizador llamado Adam para ajustar mi payload a la fuerza, pero fue un dolor de cabeza total.

Adam acumula inercia con sus cálculos. Como el paisaje matemático de esta red era tan volátil, el optimizador se volvía loco, amplificaba el ruido y me destruía por completo la data original.

### Solución: PGD al rescate

Ahí me di cuenta de que Adam era el problema. Había que ser mucho más sutil en vez de intentar forzar la convergencia a lo bruto.

Usé una técnica llamada PGD (Projected Gradient Descent), pero fijándome **solo en la dirección** del error (el signo) y no en su tamaño. Así daba pasitos cortos y seguros hacia la solución.

Armé este script para correr todo en mi infra. Un tip: tuve que forzar la instalación de PyTorch versión CPU porque la normal pesa como 3GB y me reventaba la memoria del `/tmp` en mi Linux local.

```python
import torch
import numpy as np
import base64
import io
import pwn
from flow import RealNVP

# ── 1. Cargar calibración y parámetros del reto ───────────────────────────────
cal         = np.load("calibration.npz")
target_margin = float(cal["target_margin"])   # ~30.0
lp_thresh1    = float(cal["lp_thresh1"])      # ~932.80
band1_lo      = float(cal["band1_lo"])        # ~1367.15
band1_hi      = float(cal["band1_hi"])        # ~1595.05

x_ref   = np.load("reference_window.npy")
x_ref_t = torch.tensor(x_ref, dtype=torch.float32).unsqueeze(0)

# ── 2. Cargar ambos modelos en modo evaluación ────────────────────────────────
def load_flow(name):
    d    = torch.load(name, map_location="cpu")
    flow = RealNVP(
        channels=d["channels"], window=d["window"],
        n_layers=d["n_layers"], hidden=d["hidden"]
    )
    flow.load_state_dict(d["state_dict"])
    flow.eval()
    for p in flow.parameters():
        p.requires_grad = False
    return flow

f0 = load_flow("flow_0.pt")
f1 = load_flow("flow_1.pt")

def log_prob_parts(flow, x):
    """Calcula log_prior, log_det y log_prob total de un flow."""
    z, log_det = flow.forward(x)
    log_prior  = -0.5 * (z ** 2).sum(dim=1) - 0.5 * flow.dim * np.log(2.0 * np.pi)
    return log_prior, log_det, log_prior + log_det

# ── 3. PGD con signo del gradiente (FGSM iterativo) ──────────────────────────
delta = torch.zeros_like(x_ref_t, requires_grad=True)
EPS   = 0.08    # Restricción máxima del ataque
ALPHA = 0.001   # Paso fijo por iteración

print("[*] Iniciando optimización PGD por Signo (Sin Adam)...")

for i in range(15000):
    if delta.grad is not None:
        delta.grad.zero_()

    x_sub = x_ref_t + delta

    _, _,  lp0 = log_prob_parts(f0, x_sub)
    _, ld1, lp1 = log_prob_parts(f1, x_sub)
    margin = lp1 - lp0

    # Penalizamos solo cuando NO se cumplen las condiciones
    loss_margin  = torch.relu(target_margin + 1.0 - margin)
    loss_lp1     = torch.relu(lp_thresh1   + 1.0 - lp1)
    loss_ld1_lo  = torch.relu(band1_lo     + 1.0 - ld1)
    loss_ld1_hi  = torch.relu(ld1 - (band1_hi   - 1.0))

    loss = loss_margin + loss_lp1 + loss_ld1_lo + loss_ld1_hi

    if loss.item() == 0:
        print(f"\n[+] Convergencia lograda en la iteración {i}")
        break

    loss.backward()

    with torch.no_grad():
        delta -= ALPHA * delta.grad.sign()   # Pasitos cortos por signo
        delta.clamp_(-EPS, EPS)              # Mantenemos la inyección casi invisible
    delta.requires_grad_(True)

# ── 4. Serializar y enviar al servidor ───────────────────────────────────────
x_final = (x_ref_t + delta).detach()
x_out = x_final.squeeze(0).numpy()

buf   = io.BytesIO()
np.save(buf, x_out)
b64_payload = base64.b64encode(buf.getvalue())

print("[*] Conectando a challs.umdctf.io:30303...")
conn = pwn.remote("challs.umdctf.io", 30303)
conn.recvuntil(b"> ")
conn.sendline(b64_payload)

print("\n[+] Respuesta del servidor:")
print(conn.recvall().decode())
```

Como el input de referencia que nos dieron ya estaba súper cerca de ser válido, este enfoque tranquilo funcionó perfecto. El modelo evolucionó y convergió en apenas 2 iteraciones sin romperse.

### Entrega del payload

El script agarró nuestro tensor adulterado, lo serializó, lo metió en base64 y se lo mandó directo al socket del server usando pwntools.

El sistema remoto evaluó nuestra data, calculó que cumplíamos todas las restricciones por un margen milimétrico, se comió el bypass y nos escupió la flag.

### Flag obtenida

```
UMDCTF{a_little_gram_schmidt_never_hurt_anybody}
```

## Aprendizajes

* Los optimizadores con momentum (como Adam) te pueden arruinar el payload si el modelo es inestable. A veces, un PGD simple guiado solo por el signo del gradiente es mucho más efectivo.
* Un ataque de caja blanca no necesita alterar casi nada la data original; usamos apenas una fracción del ruido permitido para engañar a los dos detectores.
* Instalar la versión ligera de PyTorch (`--index-url https://download.pytorch.org/whl/cpu`) salva bastante cuando trabajas en entornos Linux que andan cortos de RAM en la partición temporal.
