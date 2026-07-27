import math, secrets, string


def generate_password(length=20, upper=True, lower=True, numbers=True, symbols=True, avoid_similar=False):
    groups = []
    if upper: groups.append(string.ascii_uppercase)
    if lower: groups.append(string.ascii_lowercase)
    if numbers: groups.append(string.digits)
    if symbols: groups.append('!@#$%^&*()-_=+')
    if not groups: raise ValueError('Select at least one character type.')
    alphabet = ''.join(groups)
    if avoid_similar: alphabet = ''.join(c for c in alphabet if c not in 'Il1O0o')
    if length < len(groups) or length > 128: raise ValueError('Choose a length between the selected groups and 128.')
    chars = [secrets.choice(group) for group in groups] + [secrets.choice(alphabet) for _ in range(length-len(groups))]
    secrets.SystemRandom().shuffle(chars)
    entropy = round(length * math.log2(len(alphabet)), 1)
    rating = 'Very Strong' if entropy >= 80 else 'Strong' if entropy >= 60 else 'Medium' if entropy >= 36 else 'Weak'
    return ''.join(chars), entropy, rating
