# A basic implementation of RSA encryption and decryption.
# Tyler Mumford, 2015

import logging as log
import math
import fractions
import random as rand

root_logger = log.getLogger()
root_logger.setLevel(log.DEBUG)
logfile = log.FileHandler('rsa-debug.log', mode="w")
logfile.setLevel(log.INFO)
console = log.StreamHandler()
console.setLevel(log.WARNING) # Set console logging level
root_logger.addHandler(console)
root_logger.addHandler(logfile)

log.debug("Logger Initialized")

BLOCK_DIGITS = 300
BLOCK_CHARS = BLOCK_DIGITS // 3
BLOCK_MAX = (10**BLOCK_DIGITS) - 1
OLD_ENCODING = "utf-8"
DEFAULT_CERTAINTY = 10 # 1 in 2**VAL chance of false prime
plaintext = "PUBLIC KEY CRYPTOGRAPHY"
ciphertext = ""

log.info("Constants Initialized")

def is_prime(x, certainty=DEFAULT_CERTAINTY):
    """Returns True if x is prime with certainty 1-1/(2**certainty).

    Implements the Rabin-Miller primality test.
    Not seeded.
    """
    if x % 2 != 1: return False

    odd_factor = x - 1
    powers_two = 0
    while odd_factor % 2 == 0:
        powers_two += 1
        odd_factor = (x - 1) // 2**powers_two

    def confirmed_composite_by(test):
        for _ in range(powers_two - 1):
            test = pow(test, 2, x)
            if test == x - 1: return False
            if test == 1: return True
        return True

    for _ in range(certainty):
        witness_maybe = rand.randint(2, x - 2)
        test = pow(witness_maybe, odd_factor, x)

        if test == 1 or test == x - 1: continue
        if confirmed_composite_by(test):
            # log.debug("is_prime:CONFIRMED COMPOSITE:" + str(x))
            # log.debug("is_prime:CONFIRMED COMPOSITE BY:" + str(test))
            return False
    
    log.debug("is_prime:PROBABLE PRIME:" + str(x))
    return True 

assert is_prime(13)
assert not is_prime(221)

def large_prime():
    """Returns a random prime number of ~150 digits.

    Not seeded.
    """
    large_number = rand.randint(6*10**149, (10**150)-1)
    # large_number = rand.getrandbits(512)
    if large_number % 2 == 0: large_number -= 1

    while not is_prime(large_number) and large_number < 10**150:
        large_number += 2
    
    if large_number > 10**150:
        # Try again.
        large_number = large_prime()
    
    return large_number

def phi_of(key_primes):
    return (key_primes[0] - 1) * (key_primes[1] - 1)

def get_exponent(coprime):
    """Returns a random int e such that gcd(e, coprime) == 1.

    Not seeded.
    """
    exp = rand.randint(10**160, 10**200)
    if exp % 2 == 0: exp -= 1

    while fractions.gcd(exp, coprime) != 1:
        exp += 2
    log.debug("get_exponent:" + str(exp))
    return exp

def get_inverse(a, mod):
    """Returns the multiplicative inverse of a, mod (mod)."""
    assert fractions.gcd(a, mod) == 1

    def extended_euclid(a, b):
        """Returns the solution (x, y) to [ax + by = gcd(a, b)].

        Credit to page 937 of the textbook.
        """
        if b == 0:
            return (1, 0)
        else:
            x_, y_ = extended_euclid(b, a % b)
            x, y = y_, x_ - (a // b) * y_
            return (x, y)

    inverse = extended_euclid(a, mod)[0] % mod
    log.debug("get_inverse:%s is inverse of %s (mod %s)", inverse, a, mod)
    return inverse

assert get_inverse(2, 5) == 3
assert get_inverse(13, 2436) == 937
assert get_inverse(1234, 56789) == 31800

def generate_keys(passphrase=None):
    """Returns a list with [private, public] keys.

    Each key is a tuple of (exp, mod).
    """
    log.info("generate_keys:Using seed \"{}\"".format(passphrase))
    rand.seed(passphrase)

    key_primes = (large_prime(), large_prime())
    modulo = key_primes[0] * key_primes[1]
    exponent = get_exponent(phi_of(key_primes))
    inverse = get_inverse(exponent, phi_of(key_primes))

    log.debug("key:" + str(key_primes))
    log.debug("modulo: " + str(modulo))
    log.debug("exponent: " + str(exponent))
    log.debug("inverse: " + str(inverse))

    assert key_primes[0] < exponent and key_primes[1] < exponent
    print(math.floor(math.log10(modulo)) + 1)
    print(len(str(key_primes[0])))
    print(len(str(key_primes[1])))
    print(modulo > 255 * 10**297)
    print(str(modulo)[:10])
    # assert math.floor(math.log10(modulo)) + 1 == 300
    assert phi_of(key_primes) % 2 == 0
    assert exponent < modulo

    log.info("Private & public keys generated.")
    return [(inverse, modulo), (exponent, modulo)]

log.info("Setup Functions Initialized")

def encrypt(plaintext, key):
    """Returns string that represents the plaintext as encrypted by key."""
    log.info("Encrypting plaintext message:" + plaintext)
    ascii_plaintext = bytes(plaintext, OLD_ENCODING)
    log.debug("encrypt:plaintext bytes:" + str(list(ascii_plaintext)))

    # Break text into blocks by BLOCK_CHARS
    blocks = []
    for i, chars in enumerate(ascii_plaintext[::BLOCK_CHARS]):
        start = BLOCK_CHARS * i
        end = BLOCK_CHARS * (i + 1)
        blocks.append(ascii_plaintext[start:end])

    log.debug("encrypt:blocks: {}".format(blocks))
    log.info("encrypt:Breaking plaintext into {} blocks".format(len(blocks)))

    blocks_encrypted = []
    for each_block in blocks:
        number_plaintext = 0
        for i, place in enumerate(list(each_block)[::-1]):
            # Convert each_block to number_plaintext
            number_plaintext += (place * 10**(i*3))
        log.debug("plaintext number:" + str(number_plaintext))

        blocks_encrypted.append(pow(number_plaintext, key[0], key[1]))

    log.debug("encrypt:blocks_encrypted: {}".format(blocks_encrypted))

    # Pad each block to BLOCK_DIGITS
    ciphertext = ""
    for each_block in blocks_encrypted:
        ciphertext += str(each_block).rjust(BLOCK_DIGITS, "0")
    log.debug("encrypt:ciphertext number:" + ciphertext)
    log.info("encrypt:Encrypted to ciphertext:{}".format(ciphertext))
    return ciphertext

def decrypt(ciphertext, key):
    """Returns the corresponding plaintext as a string."""
    log.debug("decrypt:Decrypting ciphertext:{}...".format(ciphertext[:10]))
    
    # Break text into blocks by BLOCK_DIGITS
    blocks = []
    for i, each_block in enumerate(ciphertext[::BLOCK_DIGITS]):
        start = BLOCK_DIGITS * i
        end = BLOCK_DIGITS * (i + 1)
        blocks.append(ciphertext[start:end])

    log.debug("decrypt:Blocks: {}".format(blocks))

    decrypted_message_chars = []

    for each_block in blocks:
        block_char_list = []
        decrypted_block = pow(int(each_block), key[0], key[1])
        log.debug("decrypt:int(each_block): {}".format(int(each_block)))
        log.debug("decrypt:decrypted_block:{}".format(decrypted_block))

        decrypted_string = str(decrypted_block)

        d_n_copy = decrypted_block
        for _ in range(math.ceil(len(decrypted_string) / 3)):
            # Evaluate 3 digits at a time to convert to string.
            place = chr(d_n_copy % 10**3)
            d_n_copy //= 10**3
            block_char_list.insert(0, place)

        decrypted_message_chars.extend(block_char_list)
    decrypted_message = "".join(decrypted_message_chars)
    log.info("decrypt:Decrypted to plaintext:{}".format(decrypted_message))
    return decrypted_message


def test_all(plaintext="insert plaintext here", passphrase=None):
    """Assert that the encryption and decryption functions are inverses."""
    private_key, public_key = generate_keys(passphrase)
    assert plaintext == decrypt(encrypt(plaintext, private_key), public_key)

log.info("Transformation Functions Initialized")
log.info("Assertions Complete")
log.info("rsa.py is ready for duty.")
log.info("")

if __name__ == "__main__":
    test_all("Cowbell")
    test_all("PUBLIC KEY CRYPTOGRAPHY")
    test_all("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    test_all("I am your father.", "vader")
    test_all("""\
Call me Ishmael. Some years ago--never mind how long precisely--having
little or no money in my purse, and nothing particular to interest me on
shore, I thought I would sail about a little and see the watery part of
the world. It is a way I have of driving off the spleen and regulating
the circulation. Whenever I find myself growing grim about the mouth;
whenever it is a damp, drizzly November in my soul; whenever I find
myself involuntarily pausing before coffin warehouses, and bringing up
the rear of every funeral I meet; and especially whenever my hypos get
such an upper hand of me, that it requires a strong moral principle to
prevent me from deliberately stepping into the street, and methodically
knocking people's hats off--then, I account it high time to get to sea
as soon as I can. This is my substitute for pistol and ball. With a
philosophical flourish Cato throws himself upon his sword; I quietly
take to the ship. There is nothing surprising in this. If they but knew
it, almost all men in their degree, some time or other, cherish very
nearly the same feelings towards the ocean with me.
""")
