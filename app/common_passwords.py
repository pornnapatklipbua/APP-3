"""A blocklist of passwords that must never be accepted.

NIST SP 800-63B recommends checking new passwords against a list of commonly
used, expected and compromised values, rather than imposing composition rules
("must contain a symbol") which push people towards predictable substitutions.

This is a compact list of the passwords that dominate every breach corpus, plus
terms specific to this site that attackers would try first. For a public
deployment, consider checking against the Pwned Passwords range API as well --
see the note in README.md.
"""

COMMON_PASSWORDS = frozenset(
    """
123456 password 123456789 12345678 12345 qwerty 1234567 111111 1234567890
123123 abc123 1234 password1 iloveyou 1q2w3e4r 000000 qwerty123 zaq12wsx
dragon sunshine princess letmein 654321 monkey 27653 1qaz2wsx 123321
qwertyuiop superman asdfghjkl trustno1 baseball football welcome shadow
master jennifer jordan hunter michael harley ranger buster soccer hockey
killer george sexy andrew charlie thomas robert access love1 amanda
matrix silver william daniel golfer summer heather hammer oliver ginger
freedom whatever secret starwars computer michelle jessica pepper zxcvbnm
asdfgh121212 samsung liverpool chelsea arsenal barcelona bandit tigger
mustang batman purple diamond internet service canada hello ashley
nicole chicken maggie pokemon banana cookie orange yellow scooter
passw0rd p@ssword p@ssw0rd password123 admin administrator root toor
guest test testing changeme default temp temporary
qazwsx 112233 121212 131313 696969 asdasd asdfasdf aaaaaa qwe123
1q2w3e 987654321 555555 666666 777777 888888 999999 101010
letmein1 iloveyou1 princess1 welcome1 monkey1 sunshine1
epilepsy seizure medical health neurology auraline
epilepsy1 seizure1 medical1 health1 auraline1
""".split()
)


def is_common(password: str) -> bool:
    candidate = password.strip().lower()
    if candidate in COMMON_PASSWORDS:
        return True
    # Padding a weak base out to the length limit ("password123456") is the
    # single most common way people get round a minimum-length rule, so the
    # base is checked too.
    stripped = candidate.rstrip("0123456789!@#$%^&*_-.")
    return len(stripped) >= 4 and stripped in COMMON_PASSWORDS
