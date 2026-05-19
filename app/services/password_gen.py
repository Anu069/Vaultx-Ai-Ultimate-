import secrets
import string
import random

def generate_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = False,
    memorable: bool = False
) -> str:
    if memorable:
        return generate_memorable_password()
    
    charset = ''
    
    if use_lower:
        chars = string.ascii_lowercase
        if exclude_ambiguous:
            chars = chars.replace('l', '').replace('o', '')
        charset += chars
    
    if use_upper:
        chars = string.ascii_uppercase
        if exclude_ambiguous:
            chars = chars.replace('I', '').replace('O', '')
        charset += chars
    
    if use_digits:
        chars = string.digits
        if exclude_ambiguous:
            chars = chars.replace('0', '').replace('1', '')
        charset += chars
    
    if use_symbols:
        charset += '!@#$%^&*()_+-=[]{}|;:,.<>?'
    
    if not charset:
        charset = string.ascii_letters + string.digits
    
    # Ensure at least one char from each selected set
    password = []
    if use_lower:
        lowers = string.ascii_lowercase
        if exclude_ambiguous:
            lowers = lowers.replace('l', '').replace('o', '')
        password.append(secrets.choice(lowers))
    if use_upper:
        uppers = string.ascii_uppercase
        if exclude_ambiguous:
            uppers = uppers.replace('I', '').replace('O', '')
        password.append(secrets.choice(uppers))
    if use_digits:
        digits = '23456789' if exclude_ambiguous else string.digits
        password.append(secrets.choice(digits))
    if use_symbols:
        password.append(secrets.choice('!@#$%^&*'))
    
    # Fill remaining
    remaining = length - len(password)
    password.extend(secrets.choice(charset) for _ in range(remaining))
    
    # Shuffle
    random.shuffle(password)
    return ''.join(password)

def generate_memorable_password() -> str:
    adjectives = ['Swift', 'Bold', 'Dark', 'Bright', 'Iron', 'Steel', 'Storm', 'Fire', 'Shadow', 'Crystal']
    nouns = ['Dragon', 'Phoenix', 'Tiger', 'Eagle', 'Wolf', 'Falcon', 'Raven', 'Viper', 'Cobra', 'Panther']
    
    adj = secrets.choice(adjectives)
    noun = secrets.choice(nouns)
    num = secrets.randbelow(9000) + 1000
    sym = secrets.choice('!@#$%')
    
    return f"{adj}{noun}{num}{sym}"

def generate_passphrase(words: int = 4) -> str:
    wordlist = [
        'apple', 'brave', 'cloud', 'dance', 'eagle', 'flame', 'grace', 'heart',
        'ivory', 'jungle', 'karma', 'lunar', 'magic', 'noble', 'ocean', 'pearl',
        'quest', 'river', 'storm', 'titan', 'ultra', 'vivid', 'wisdom', 'xenon',
        'yacht', 'zeal', 'amber', 'blaze', 'crisp', 'delta', 'ember', 'frost',
        'gleam', 'haven', 'index', 'jewel', 'knack', 'lumen', 'marsh', 'nexus',
        'orbit', 'prism', 'quartz', 'ridge', 'swift', 'talon', 'urban', 'vault',
        'whirl', 'xerox', 'yield', 'zenith', 'azure', 'birth', 'cipher', 'dusk'
    ]
    selected = [secrets.choice(wordlist) for _ in range(words)]
    num = secrets.randbelow(999) + 1
    return '-'.join(selected) + f'-{num}'
