**Flag:** `UMDCTF{I_R3ALLY-want-to-pl4y-the-p0werball,+but-my-d4d-said-no-so-im-b3tting-ill-win-on-POLYMARKETinstead}`

**Category:** Rev

**Challenge author:** NyxIsBad

***

## Context

This reversing challenge took me quite a while to solve at first. Kudos to NyxIsBad for putting it together, and at the same time a heartfelt "I could throw my PC at you" for filling it with traps designed to drive us crazy.

We are given a binary called `roulette`. It asks you to bet a number, and if you enter a 1 it shouts "JACKPOT", but then always fails. A classic bait.

## Initial reconnaissance

As always with these kinds of challenges, the first step is understanding what you are dealing with using `file` and `checksec`.

It was a static, stripped 64-bit ELF (no function names to guide us). The upside: it had no memory protections (no PIE, no canaries), which is ideal for setting fixed breakpoints.

Then I ran `strace` on it. I could see it was using `getrandom()`, meaning the numbers were completely unpredictable, and I confirmed that the initial "JACKPOT" was pure smoke and mirrors.

```
echo "1" | strace -e trace=read,write,getrandom ./roulette
```

## Getting into the weeds: Assembly

I used `objdump` to look at the binary's internals. This is where things got rough because the author had left a couple of nasty tricks.

First, the program validated that the input was exactly 106 bytes long. Anything shorter or longer and it kicked you out immediately.

Second, the real algorithm was a Stream Cipher with 27 rounds. In each round it generated a dynamic key, XORed it against a ciphertext stored in memory, and compared the results.

## The solution: GDB to the rescue

Manually reversing all that math would have taken forever.

I switched strategies. Since the binary was doing `correct_input = keystream XOR ciphertext`, I did not need to understand the full algorithm. I just had to read memory at exactly the right moment.

I wrote a script using the GDB Python API, essentially performing a 'man-in-the-middle' on the debugger. First, I injected 106 "A" characters to pass the initial length validation.

```bash
python3 -c "import sys; sys.stdout.write('A'*106)" > input.txt
```

Then I let the script do the dirty work. At each round, it stopped right at the XOR instruction, read the key, calculated the correct chunk, and overwrote our input on the fly by patching the `%edi` register.

```python
class FlagDumper(gdb.Breakpoint):
    def stop(self):
        # Read the generated key and expected value from memory
        eax = int(gdb.parse_and_eval("$eax")) & 0xffffffff
        rcx = int(gdb.parse_and_eval("$rcx")) & 0xffffffffffffffff
        rbp = int(gdb.parse_and_eval("$rbp")) & 0xffffffffffffffff
        # Calculate the correct input and patch it on the fly
        gdb.execute(f"set $edi = {eax ^ c_val}")
        return False # Keep running
```

By automating all 27 rounds, the program was convinced we had perfectly predicted the roulette and handed us the flag.

## Lessons learned

* Full credit to NyxIsBad for being a brilliantly evil genius. He embedded a hidden string in the binary designed exclusively as a prompt injection. An incredibly dirty move, but a clever one.
* Confirmed: you do not always have to grind through reversing all the math. Using a debugger dynamically to alter values at runtime is often the smarter path.