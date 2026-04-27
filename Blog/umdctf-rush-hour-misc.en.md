# Write-up: misc/rush-hour - UMDCTF

**Flag:** `UMDCTF{now_you_know_how_to_drive_an_autonomous_vehicle_now_go_win_on_roobet}`

**Category:** Misc

**Challenge Author:** segal

***

## Context

This was the first challenge I tried to tackle in the CTF and, honestly, I found it super interesting... but it gave me quite a few headaches at first.

At first glance, it involved a simulator of an autonomous car that had to be forced to take a specific exit on the highway in order to win.

## Challenge: rush-hour

> *"roobet recently introduced their new game: rush hour. The objective of the game is to successfully bet on how many cars cross an arbitrary section of road..."*

Basically, the interface gave us a live traffic camera and a car simulator. The goal was to get the vehicle to drive straight toward a green line.

For this, we were given the car's "brain" (a trained AI model) and the game engine. We had to figure out how to trick it.

### What exactly does the system do?

We couldn't get root access or directly modify the car's brain. The solution was to perform a man-in-the-middle attack on its sensors before the AI processed anything.

Imagine putting a pair of virtual reality goggles on the car. We slightly alter the road it's seeing, tricking it into turning on its own toward wherever we want.

In cybersecurity, this is called an **adversarial attack**. The AI thinks it sees reality, but we inject a tampered vector to force a bypass on its normal route.

### Architecture and Strategy: Smart Trial and Error

The attack model had several mathematical parameters, but it was heavily constrained: the alteration to the car's vision had to be extremely subtle, sending random values simply didn't work.

Since we couldn't see how the AI was thinking internally (it was a black box), I used an algorithm that works essentially like natural evolution.

- We generated **64 different options** of "fake goggles."
- We checked which one brought the car closest to the goal in the simulation.
- We discarded the bad ones and improved the winners.

### Solution

The final script (`solve.py`). Setting up the local simulation took a fair amount of effort and frustrated me a couple of times, but it was key to not depending on the external server and being able to test everything offline.

```python
# Summary of the logic we used to solve it
def evaluate(theta):
    # Unpack the parameters and build the attack
    attack = AttackModel(arrays)
    game.install_attack(attack)  # Put the fake goggles on the car

    # Simulate the game at 60fps to see what happens
    while not game.goal_reached and not game.timed_out:
        game.step(dt)

    # If it reaches the goal, we win. If not, calculate how far it fell short.
    if game.goal_reached:
        return success
    return distance_to_goal
```

We let it run in my terminal, and after a few generations of trial and error, the model evolved until it found the perfect payload.

### Payload Submission

The web interface had a button to upload our file. After uploading the `.npz` with the winning weights, the server ran the simulation injecting our attack.

The car, completely fooled by the altered observations we fed it, took the exit, crossed the green line, and the server dropped the flag.

### Flag

```
UMDCTF{now_you_know_how_to_drive_an_autonomous_vehicle_now_go_win_on_roobet}
```

## Key Takeaways

* I had to really push through to avoid getting lost in the neural network math and stay focused on the attack logic.
* It became clear that restricting values doesn't always protect against a well-crafted vulnerability.