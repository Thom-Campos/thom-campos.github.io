**Flag:** `UMDCTF{now_you_know_how_to_drive_an_autonomous_vehicle_now_go_win_on_roobet}`

**Categoría:** Misc

**Autor del Reto:** segal

***

## Contexto

Este fue el primer desafío que traté de hacer en el CTF y, la verdad, me pareció súper interesante, pero me dio varios dolores de cabeza al principio.

A simple vista, trataba de un simulador de un auto autónomo al que había que obligar a tomar una salida específica en la autopista para ganar.

## Desafío: rush-hour

```"roobet recently introduced their new game: rush hour. The objective of the game is to successfully bet on how many cars cross an arbitrary section of road..."```

Básicamente, la interfaz nos daba una cámara de tráfico en vivo y un simulador del auto. El objetivo era lograr que el vehículo fuera directo hacia una línea verde.

Para esto, nos pasaron el "cerebro" del auto (un modelo de IA entrenado) y el motor del juego. Teníamos que ingeniárnoslas para engañarlo.

### ¿Qué hace exactamente el sistema?

Aquí no podíamos sacar root ni modificar el cerebro del auto directamente. La solución era hacerle un man-in-the-middle a sus sensores antes de que la IA procesara todo.

Imagínense que le ponemos unos lentes de realidad virtual al auto. Le alteramos un poquito la calle que está viendo, engañándolo para que doble solo hacia donde queremos.

Esto en ciberseguridad se llama **ataque adversario**. La IA cree que ve la realidad, pero le inyectamos un vector adulterado para forzar un bypass en su ruta normal.

### Arquitectura y Estrategia: Prueba y error inteligente

El modelo de ataque tenía varios parámetros matemáticos, pero estaba muy limitado: la alteración a la visión del auto tenía que ser súper sutil, no servía mandar valores al azar.

Como no podíamos ver cómo pensaba la IA por dentro (era una caja negra), usé un algoritmo que funciona básicamente como la evolución natural.

- Generábamos **64 opciones distintas** de "lentes falsos".
- Veíamos cuál acercaba más al auto a la meta en la simulación.
- Descartábamos a los malos y mejorábamos a los ganadores.

### Solución

El script final (`solve.py`). Armar la simulación local me costó bastante y me frustré un par de veces, pero era clave para no depender del server externo y probar todo offline.

```python
# Resumen de la lógica que usamos para resolverlo
def evaluate(theta):
    # Desempacamos los parámetros y armamos el ataque
    attack = AttackModel(arrays)
    game.install_attack(attack)  # Le ponemos los lentes falsos al auto

    # Simulamos el juego a 60fps a ver qué pasa
    while not game.goal_reached and not game.timed_out:
        game.step(dt)

    # Si llega a la meta, ganamos. Si no, calculamos qué tan lejos quedó.
    if game.goal_reached:
        return exito
    return distancia_a_la_meta
```

Lo dejamos corriendo en mi terminal, y después de unas cuantas generaciones de prueba y error, el modelo evolucionó hasta encontrar el payload perfecto.

### Entrega del payload

La interfaz web tenía un botón para subir nuestro archivo. Al subir el `.npz` con los pesos ganadores, el servidor corrió la simulación inyectando nuestro ataque.

El auto, totalmente engañado por las observaciones que le alteramos, tomó la salida, pisó la línea verde y el servidor nos soltó la flag.

### Flag obtenida

```
UMDCTF{now_you_know_how_to_drive_an_autonomous_vehicle_now_go_win_on_roobet}
```

## Aprendizajes

* Tuve que cabecear harto para no perderme en la matemática de la red neuronal y enfocarme en la lógica del ataque.
* Quedó claro que restringir valores no siempre protege contra una buena vulnerabilidad.
