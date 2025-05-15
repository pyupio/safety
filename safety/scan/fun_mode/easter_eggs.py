import random
import time
import os
from safety.scan.fun_mode.celebration_effects import CELEBRATION_EFFECTS

# -----------------------------
# Data: ASCII Arts, Fortunes, EMOJIS, etc.
# -----------------------------

ASCII_ARTS = {
    "ascii": [
        # Hedgehog guarding a shield
        r"""
        /\     /\
       {  `---'  }
       {  O   O  }
       ~~>  V  <~~
        \  \|/  /
         `-----'__
         /     \  `^\_
        {       }\ |\_\_   *Safely Protected from vulnerabilities!*
        |  \_/  |/ /  \_\_
         \__/  /(_E     \__/
           (  /
            MM
        """,
        # Cat with a shield
        r"""
       /\_/\
     =( °w° )=   *Purrr... no vulnerabilities dare to cross!*
      (   *   )
     ---(   )---
        /     \
       /  ^    \
      ( (   )   )
       \_) |_(_/
      __||___||__
     |           |
     |   SAFE    |
     |    &      |
     |  SECURE!  |
     |___________|
        /     \
       |       |

        """,
        # Bunny with a shield
        r"""
     (\_/)
     ( •_•)  *Hop-hop! SafetyCLI ready, no vulns here!*
    ( >:carrot:< )
     /     \
    / |   | \
   /  |   |  \
  /   |___|   \
 (               )
  \____|||_____/
       ||||
      __||__
     |      |
     | SAFE |
     | FROM |
     | BUGS |
     |______|

        """,
        # Dog behind a shield
        r"""
         / \__
        (    o\____
        /         O
       /   (_______/    *Woof! Our shield is strong, no vulns inside!*
      /_____/


        """,
    ]
}

FORTUNES = [
    "Your dependencies are safer than a password-manager's vault.",
    "Your code sparkles with zero known vulnerabilities!",
    "All vulnerabilities fear your security prowess!",
    "Your build is as solid as a rock!",
    "Your code is a fortress; no bug can breach it.",
    "In the realm of code, you are the vigilant guardian.",
    "Each line you write fortifies the castle of your code.",
    "Your code is a well-oiled machine, impervious to rust.",
    "Your code is a symphony of security and efficiency.",
    "Your code is a beacon of safety in the digital ocean.",
    "Your code is a masterpiece, untouched by the hands of vulnerabilities.",
    "Your code stands tall, a citadel against cyber threats.",
    "Your code is a tapestry woven with threads of safety.",
    "Your code is a lighthouse, guiding ships away from the rocks of vulnerabilities.",
    "Your code is a garden where no weeds of bugs can grow.",
    "In the realm of software, your security measures are legendary.",
]


EMOJIS = [
    ":dog_face:",
    ":dog2:",
    ":guide_dog:",
    ":service_dog:",
    ":poodle:",
    ":wolf:",
    ":fox_face:",
    ":cat_face:",
    ":cat2:",
    ":cat2:",
    ":lion_face:",
    ":tiger_face:",
    ":tiger2:",
    ":leopard:",
    ":horse_face:",
    ":deer:",
    ":deer:",
    ":racehorse:",
    ":unicorn_face:",
    ":zebra:",
    ":deer:",
    ":bison:",
    ":cow_face:",
    ":ox:",
    ":water_buffalo:",
    ":cow2:",
    ":ram:",
    ":sheep:",
    ":goat:",
    ":dromedary_camel:",
    ":two-hump_camel:",
    ":llama:",
    ":giraffe:",
    ":elephant:",
    ":mammoth:",
    ":rhinoceros:",
    ":hippopotamus:",
    ":mouse_face:",
    ":mouse2:",
    ":rat:",
    ":hamster:",
    ":rabbit_face:",
    ":rabbit2:",
    ":chipmunk:",
    ":beaver:",
    ":hedgehog:",
    ":bat:",
    ":bear:",
    ":polar_bear:",
    ":koala:",
    ":panda_face:",
    ":otter:",
    ":kangaroo:",
    ":badger:",
    ":turkey:",
    ":chicken:",
    ":rooster:",
    ":baby_chick:",
    ":hatched_chick:",
    ":bird:",
    ":penguin:",
    ":dove:",
    ":eagle:",
    ":duck:",
    ":swan:",
    ":owl:",
    ":dodo:",
    ":flamingo:",
    ":peacock:",
    ":parrot:",
    ":bird:",
    ":goose:",
    ":phoenix:",
    ":frog:",
    ":crocodile:",
    ":turtle:",
    ":lizard:",
    ":dragon:",
    ":sauropod:",
    ":t-rex:",
    ":whale:",
    ":whale2:",
    ":flipper:",
    ":seal:",
    ":fish:",
    ":tropical_fish:",
    ":blowfish:",
    ":shark:",
    ":octopus:",
    ":jellyfish:",
    ":crab:",
    ":lobster:",
    ":squid:",
    ":snail:",
    ":butterfly:",
    ":bug:",
    ":bee:",
]

# -----------------------------
# Helper functions (Effects)
# -----------------------------


def show_race(console):
    # Pick two different EMOJIS at random
    emoji1, emoji2 = random.sample(EMOJIS, 2)
    finish_line = 50
    pos1 = 0
    pos2 = 0

    console.print("Ready... Set... Go!", style="bold cyan")
    time.sleep(1)
    console.clear()

    while True:
        # Move contestants forward by random increments
        pos1 += random.randint(1, 3)
        pos2 += random.randint(1, 3)

        console.clear()
        console.print("[green]Finish line[/green]" + " " * (finish_line - 10) + "|")
        line1 = " " * pos1 + emoji1
        line2 = " " * pos2 + emoji2
        console.print(f"{emoji1} lane:  {line1}")
        console.print(f"{emoji2} lane:  {line2}")

        time.sleep(0.3)

        finished1 = pos1 >= finish_line
        finished2 = pos2 >= finish_line

        if finished1 and finished2:
            console.print(
                "It's a tie! Both reached the finish line at the same time!",
                style="bold magenta",
            )
            break
        elif finished1:
            console.print(
                f"The {emoji1} wins! Slow and steady (or maybe fast?), it prevailed!",
                style="bold green",
            )
            break
        elif finished2:
            console.print(
                f"The {emoji2} wins! Speed and agility triumphed!", style="bold green"
            )
            break

    time.sleep(2)
    console.clear()
    console.print("Hope you enjoyed the race! :party_popper:", style="bold cyan")


# -----------------------------
# Main Easter Egg Dispatcher
# -----------------------------


def run_easter_egg(console, exit_code: int) -> None:
    """
    Runs an easter egg based on the SAFETY_FUN_MODE environment variable.
    This function can be easily removed or commented out.
    """
    egg_mode = os.getenv("SAFETY_FUN_MODE", "").strip().lower()

    allowed_modes = {"ascii", "fx", "race", "fortune"}

    if exit_code == 0 and egg_mode in allowed_modes:
        if egg_mode == "ascii":
            art = random.choice(ASCII_ARTS["ascii"])
            console.print(art, style="green")

        elif egg_mode == "fx":
            effect = random.choice(CELEBRATION_EFFECTS)
            effect(console)  # Run the randomly selected effect

        elif egg_mode == "race":
            show_race(console)

        elif egg_mode == "fortune":
            fortune_message = random.choice(FORTUNES)
            console.print(f"\n[italic cyan]{fortune_message}[/italic cyan]\n")
