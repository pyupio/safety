import random
import time
from rich.text import Text
from rich.style import Style

# -----------------------------
# Celebration Effects
# -----------------------------


def show_confetti(console):
    # Characters to use as confetti
    chars = ["*", "o", "+", "~"]
    width = console.size.width
    height = console.size.height

    frames = 10
    for _ in range(frames):
        console.clear()
        for __ in range(random.randint(50, 100)):  # number of confetti pieces
            x = random.randint(0, max(0, width - 1))
            y = random.randint(0, max(0, height - 2))
            char = random.choice(chars)
            color = random.choice(["red", "green", "yellow", "blue", "magenta", "cyan"])
            console.print(
                Text(char, style=Style(color=color)),
                end="",
                style=color,
                justify="left",
                overflow="ignore",
                no_wrap=True,
                soft_wrap=False,
            )
            console.file.write(f"\x1b[{y};{x}H")  # Move cursor to position
        console.file.flush()
        time.sleep(0.3)
    console.clear()
    console.print(
        "The confetti has settled! Congrats on a clean scan!", style="bold green"
    )


def show_trophy(console):
    """Displays a celebratory trophy with sparkles."""
    trophy = (
        r"""
       ___________
      '._==_==_=_.'
      .-\:      /-.
     | (|:.     |) |
      '-|:.     |-'
        \::.    /
         '::. .'
           ) (
         _.' '._
        `"""
        """"`
    """
    )
    for _ in range(5):  # Trophy animation
        console.clear()
        sparkles = random.choice(
            [":sparkles:", ":glowing_star:", ":dizzy:", ":party_popper:"]
        )
        console.print(trophy, style="bold yellow")
        console.print(
            f"{sparkles} Scan Complete! No vulnerabilities found! {sparkles}",
            style="bold green",
            justify="center",
        )
        time.sleep(0.5)
    console.print("Your code is SAFE and SOUND! :trophy:", style="bold yellow")


def show_balloons(console):
    """Displays celebratory balloons popping."""
    balloons = [":balloon:", ":party_popper:", ":sparkles:", ":collision:"]
    width = console.size.width

    for _ in range(10):  # Number of balloons
        console.clear()
        for __ in range(random.randint(5, 10)):  # Balloons per frame
            x = random.randint(0, width - 1)
            balloon = random.choice(balloons)
            console.print(
                Text(balloon, style=Style(color="yellow")), end="", overflow="ignore"
            )
            console.file.write(f"\x1b[{random.randint(1, 10)};{x}H")
        console.file.flush()
        time.sleep(0.5)
    console.print(
        ":balloon: POP! :party_popper: No vulnerabilities detected!", style="bold green"
    )


def show_victory_parade(console):
    """Displays a victory parade of emojis."""
    parade = [
        ":party_popper:",
        ":confetti_ball:",
        ":trophy:",
        ":partying_face:",
        ":sparkles:",
        ":laptop_computer:",
        ":locked:",
        ":white_heavy_check_mark:",
    ]
    width = console.size.width

    for _ in range(20):  # Duration of parade
        console.clear()
        line = " ".join(random.choices(parade, k=width // 2))
        console.print(line, style="bold green", justify="center")
        time.sleep(0.2)

    console.print(
        "The parade is over. Your code is safe! :trophy:", style="bold yellow"
    )


def show_confetti_rain(console):
    """Displays a colorful confetti rain effect."""
    colors = ["red", "green", "yellow", "blue", "magenta", "cyan", "white"]
    width = console.size.width

    for _ in range(10):  # Number of confetti frames
        console.clear()
        for __ in range(100):  # Confetti pieces per frame
            x = random.randint(0, width - 1)
            char = random.choice(["*", "+", "~", ":sparkles:", "o"])
            color = random.choice(colors)
            console.print(
                Text(char, style=Style(color=color)), end="", overflow="ignore"
            )
            console.file.write(f"\x1b[{random.randint(1, 10)};{x}H")
        console.file.flush()
        time.sleep(0.3)

    console.print(
        ":party_popper: Confetti celebration complete! You're vulnerability-free! :party_popper:",
        style="bold cyan",
    )


def show_fireworks_display(console):
    """Displays a celebratory fireworks animation."""
    fireworks = [
        ":collision:",
        ":sparkles:",
        ":glowing_star:",
        ":fireworks:",
        ":sparkler:",
    ]
    width = console.size.width

    for _ in range(15):  # Number of fireworks
        x = random.randint(5, width - 5)
        y = random.randint(2, 8)
        firework = random.choice(fireworks)
        color = random.choice(["red", "yellow", "green", "blue", "magenta"])
        console.print(
            Text(firework, style=Style(color=color)), end="", overflow="ignore"
        )
        console.file.write(f"\x1b[{y};{x}H")  # Position fireworks
        console.file.flush()
        time.sleep(0.3)

    console.print(
        ":fireworks: Fireworks display finished! Code is secure! :fireworks:",
        style="bold magenta",
    )


def show_star_trail(console):
    """Displays a shooting star trail effect."""
    stars = [":white_medium_star:", ":glowing_star:", ":sparkles:", ":dizzy:"]
    width = console.size.width

    for _ in range(10):  # Number of shooting stars
        console.clear()
        start_x = random.randint(0, width // 2)
        trail = "".join(random.choices(stars, k=10))
        console.print(f"{' ' * start_x}{trail}", style="bold yellow", justify="left")
        time.sleep(0.3)

    console.print(
        ":sparkles: Your code shines bright with no vulnerabilities! :sparkles:",
        style="bold cyan",
    )


def show_celebration_wave(console):
    """Displays a celebratory wave effect with emojis."""
    emojis = [
        ":party_popper:",
        ":confetti_ball:",
        ":sparkles:",
        ":partying_face:",
        ":balloon:",
    ]
    width = console.size.width
    wave = [random.choice(emojis) for _ in range(width)]

    for _ in range(10):  # Number of waves
        console.clear()
        line = "".join(wave)
        console.print(line, style="bold yellow", justify="center")
        wave.insert(0, wave.pop())  # Shift wave
        time.sleep(0.3)

    console.print(
        ":water_wave: Celebration wave ends! Your scan is clean! :glowing_star:",
        style="bold green",
    )


# List of all celebratory effects
CELEBRATION_EFFECTS = [
    show_confetti,
    show_trophy,
    show_balloons,
    show_victory_parade,
    show_confetti_rain,
    show_fireworks_display,
    show_star_trail,
    show_celebration_wave,
]
