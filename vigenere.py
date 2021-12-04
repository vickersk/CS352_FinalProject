'''
CS 352 Final Project
Vignere Cryptosystem implemented in Python

Description:
The Vigenere cipher is a substitution cipher that uses a keyword to shift
each letter forward in the plaintext by the number correspondence of each
letter in the keyword. This is similar to a Caesar cipher which shifts each
letter in a message by the same number of places. The Vigenere cipher differs
in that the number of places a letter is shifted forward is based on the
corresponding letter in the keyword and to fully encrypt the plaintext the
keyword is repeated across the message. The keyword can be used to decrypt
by shifting each letter in the ciphertext backwards by the corresponding
letter in the keyword.

Example inputs can be found in vignere_julia_cases.txt in the test_cases folder.

Author: Kai Vickers
Last Modified: 12/1/2021
'''

from sre_constants import ASSERT
import sys
import re
import math
import timeit, functools

# Global Constants:
# String containing all the lower case letters in the English alphabet
ALPHABET = 'abcdefghijklmnopqrstuvwxyz'

# Number of letters in the English alphabet
NUM_LETTERS = 26

# ASCCI number of lowercase 'a' to start at 1
ASCII_OFFSET = 97

# Order of letters by decreasing frequency of appearance in a message
FREQ_ORDER = 'etaoinshrdlcumwfgypbvkjxqz'

def mod_26(x: int) -> int:
    '''
    mod_26

    Helper function used for perfroming modulo 26 on the elements of
    a matrix or vector.

    Parameters:
        x - the value to perfrom modulo 26 on

    Returns:
        The resulting value
    '''

    return x % NUM_LETTERS

def analyze_frequency(cipher_text: str) -> list:
    '''
    analyze_frequency

    Takes in a cipher text message and returns an array containing the
    number of occurences for each character in the cipher text, where
    the character corresponds to the index of the array.

    Parameters:
        cipher_text - the encrypted message string

    Returns:
        An array containing the number of occurences for each character
    '''

    # Initializes the frequency array to all zeros to
    # store the number of occurences of each letter
    frequency_array = [0] * NUM_LETTERS

    ct_len = len(cipher_text)

    # Iterates through each character in the plain text and
    # increments the value of the frequency array of each
    # character it comes across
    for i in range(0, ct_len):

        # Extracts the character from the plain text
        char = cipher_text[i]

        # Checks if the char is exclusively a lowercase letter
        if char in ALPHABET:

            # Adds 1 to the corresponding spot of the character
            # in the frequenct array
            char = ord(char) - ASCII_OFFSET
            frequency_array[char] += 1

    return frequency_array

def calculate_IC(cipher_text: str) -> float:
    '''
    calculate_IC

    Takes in a cipher text message and calculates the index of coincidence
    value (IC value) for the message, which is the probability that two
    letters are the same. The IC value is calculated using the following
    formula:

        IC = Sum(i=1 to 26) [ ni * (ni - 1)] / [n (n - 1)]

        where ni is the number of occurences for the specific letter and
        n is the total length of the message

    Parameters:
        cipher_text - the encrypted message string

    Returns:
        The resulting IC value
    '''

    cipher_text = cipher_text.replace(' ', '')
    cipher_text = cipher_text.lower()
    ct_len = len(cipher_text)

    # Computes the frequency array of the plain text
    frequency_array = analyze_frequency(cipher_text)

    sum = 0

    # Sums the numerator of the formula
    for n in frequency_array:
        sum += (n * (n - 1))

    # If the plain text is empty the IC value is 0,
    # otherwise, it divides the summation by the
    # denominator of the formula
    if ct_len == 0:
        return 0.0
    else:
        ic = sum / (ct_len * (ct_len - 1))

    return ic

"""
factors

Takes in a number and produces an array of all its existing factors.
Factors that are improbable key lengths are ignored, such as 1 and 2.

Parameters:
    x - the number to factorize

Returns:
    An array of factors
"""
def factors(x: int) -> list:

    # Stores the factors
    factors = []

    # Loops through all possible numbers up to x and
    # checks if the number is divisible by the index
    for i in range(1, x + 1):

        # If the number is divisible, its added to the factors
        if x % i == 0 and i != 1 and i != 2:
            factors.append(i)

    return factors

def kasiski_test(cipher_text: str) -> list:
    '''
    kasiski_test

    Takes in a cipher text and returns an array of possible key lengths
    based on the distances between reoccuring substrings in the cipher text.
    If the cipher text has no repeating substrings, this test doesn't produce
    useful information for determining the key length. Otherwise said, this
    function is applicable if the cipher text has repeated substrings.

    Parameters:
        cipher_text - message string to be encrypted

    Returns:
        An array of possible key lengths
    '''

    cipher_text = cipher_text.replace(' ', '')
    ct_len = len(cipher_text)

    # Initializes an empty dictionary for all the substrings of the plain text
    substring_occur = {}

    # Iterates through every possible substring of length 3 or greater
    # in the plain text and adds an entry to the substring_occur
    # dictionary with the number of occurences
    for i in range(0, ct_len):
        for l in range((i + 3), ct_len):

            # Gets the substring
            substring = cipher_text[i:l]

            # Gets the number of occurences of the substring in the plain text
            occur = cipher_text.count(substring)

            # If there are more than two occurences of the substring,
            # it gets stored
            if occur >= 2:
                substring_occur[substring] = occur

    # Initializes an empty array of distance values between substring occurences
    distances = []

    # Gets the substrings that have two or more occurences
    substrings = substring_occur.keys()

    for substring in substrings:

        # Gets a vector of all the substring indices
        indices = [s.start() for s in re.finditer(substring, cipher_text)]

        # Gets the number of index pairs
        indices_len = len(indices) / 2

        # Iterates through each index pair and substracts the starting index
        # of the first occurene from the starting index of the next occurence
        for i in range(0, indices_len):

            # Calculates the distance
            dist = indices[i - 1] - indices[i]

            # Adds the distance to the array of distances
            distances.append(dist)

    # Gets the number of distane values
    num_distances = len(distances)

    # Initializes an empty set of greatest common divisors
    gcds = set()

    # Calculates multiple r values by taking the gcd between each
    # distance. This could be implemented using merge sort to make
    # it faster.
    for i in range(0 , num_distances - 1):
        for j in range((i + 1), num_distances):

            # Calculates the value of r
            r = math.gcd(distances[i], distances[j])

            # If the r value is 1 or less, it gets ignored
            if r > 1:

                # Adds the r value to the set of gcds
                gcds.add(r)

    # Sorts the gcds in ascending order
    gcds = sorted(gcds)

    # If gcds is empty, nothing is returned. This occurs when
    # the only r value is 1 that is calculated.
    if not gcds:
        return None
    else:
        return gcds

def _IC_test(n: int, _IC: float) -> float:
    '''
    _IC_test

    Takes in the length of a cipher text and the corresponding IC value of the
    cipher text, and computes a probable keylength used to decrypt the cipher text.
    The probable keylength, r, is computed using the following formula:

                            0.027 * n
        r   ~=    -----------------------------------
                (n - 1) * IC - 0.038 * n + 0.065


    Parameters:
        n - the length of the cipher text
        _IC - the corresponding IC value of the cipher text

    Returns:
        r - the probable keylength used to encrypt
    '''

    # Computes r, which is the length of the keyword or an approximation of it.
    r = 0.027 * n / (((n - 1) * _IC) - (0.038 * n) + 0.065)

    return r

def decrypt(cipher_text: str, keyword: str) -> str:
    '''
    decrypts

    Takes in a cipher text and keyword, and uses the keyword to decrpyt the
    cipher text back to the original plain text by shifting each character
    "backwards" using the corresponding value of the letter in the keyword.

    Parameters:
        cipher_text - encrypted plain text using the Vigenere system
        keyword - the keyword used to encrypt the cipher text

    Returns:
        The resulting deciphered plain text
    '''

    # Gets the length of the plain text and the keyword
    ct_length = len(cipher_text)
    key_length = len(keyword)

    # Stores the encrypted cipher text
    plain_text = ""

    # Iterates through each letter in the plain text and encrypts the letter
    # by shifting it the amount of the corresponding letter in the keyword
    for i in range(0, ct_length):

        # Gets the index of the keyword
        j = i % key_length

        # Gets the new character value from the shift
        new_char = mod_26(ord(cipher_text[i]) - ord(keyword[j]))

        # Appends the character to the end of the cipher text string
        plain_text = plain_text + chr(new_char + ASCII_OFFSET)

    return plain_text

def brute_force(cipher_text: str, plain_text: str) -> str:
    '''
    decrypt

    Attempts to decrypt a cipher text message by performing the IC and
    Kasiski tests to find a probable keylength. Using this probable
    key length, the text is split up into

    The following code was modified from the following source:
    https://www.geeksforgeeks.org/find-closest-number-array/

    Parameters:
        arr - the array to examine
        target - the target value

    Returns:
        The value in the array thats closest to the target value
    '''

    ct_length = len(cipher_text)

    # Performs the Kasiski length and gets the probable key lengths
    key_lengths = kasiski_test(cipher_text)

    probable_lengths = []

    # Calculates the IC value of the cipher text
    _IC = calculate_IC(cipher_text)

    # Calculates the r value of the cipher text, given the
    # length of the text and IC value
    r = _IC_test(ct_length, _IC)

    # Checks if the Kasiski test was successful
    # (If the cipher text has repeated substrings)
    if key_lengths is None:

        # Ensures that r is non-negative
        if r > 0:
            # Converts r to an integer
            probable_lengths = math.floor(r)

        # If r is negative, its not possible to determine the keyword anymore
        else:
            return None
    else:
        probable_lengths = key_lengths

    found_key = None

    # Loops through all possible probabale lengths
    for probable_len in probable_lengths:

        # Stores the keyword for this probable length
        found_key = ""

        # Initializes a Vector of Vectors of monoalphabetic schemes
        ma_columns = []

        # Intializes the monoalphabetic schemes
        for _ in range(0, probable_len):

            # Initializes the character vector
            char_lst = []

            # Adds the character vector to the scheme
            ma_columns.append(char_lst)

        # Adds the characters of the cipher text to their respective
        # monoalphabetic schemes
        for i in range(0, ct_length):

            j = i % probable_len

            ma_columns[j].append(cipher_text[i])

        # The index of the cipher text and plain text
        k = 1

        # Loops through each character in the probable length
        for i in range(0, probable_len):

            # Extracts the column values
            col = ma_columns[i]

            # Performs frequency analysis on the column
            freq = analyze_frequency(col)

            sort = [x for _, x in sorted(zip(freq, col))]

            for j in range(0, NUM_LETTERS):

                # Creates the shift char from the first character of the sorted column
                # and the current character in the frequenct order
                sort_char = ord(sort[1]) - ASCII_OFFSET
                f_char = ord(FREQ_ORDER[j]) - ASCII_OFFSET

                # Calculates the shift value between the sorted column and
                # frequency order of characters
                shift = mod_26(sort_char - f_char)

                # Gets the character of the shift value
                key_char = chr(shift + ASCII_OFFSET)

                # Decrypts the first letter of the cipher text using
                # the keywrod character
                decrypt_char = decrypt(cipher_text[k], key_char)

                # If the resulting decrypted character is the same as the plain text
                # character in the corresponding position, the keyword character is
                # added to the found key string
                if decrypt_char == str(plain_text[k]):

                    found_key = found_key + key_char

                    # If the found key string is equal to the length of the cipher
                    # text, it returns the found key which shows the repetition
                    if len(found_key) == ct_length:
                        return found_key

                    # Increments k for the next character
                    k += 1

    # If the found key wasn't completely found, it returns whatever is present
    if len(found_key) > 0:
        return found_key

    # None is returned if the brute force was unsuccessful
    else:
        return None

def encrypt(plain_text: str, key: str) -> str:
    '''
    encrypts

    Encrypts a given plain text by shifting each character of the
    plaintext by the corresponding the numerical value of the
    corresponding character of the keyword. Once the end of the
    keyword has been reached, the keyword is repeated to encrypt the
    rest of the plain text.

    Parameters:
        plain_text - message string to be encrypted
        keyword - the keyword for encrypting the plain text

    Returns:
        The resulting enciphered cipher text
    '''
    
    # Gets the length of the plain text and the keyword
    pt_length = len(plain_text)
    key_length = len(key)

    # Stores the encrypted cipher text
    cipher_text = ""

    # Iterates through each letter in the plain text and encrypts the letter
    # by shifting it the amount of the corresponding letter in the keyword
    for i in range(0, pt_length):

        # Gets the index of the keyword
        j = i % key_length

        # Gets the new character value from the shift
        new_char = mod_26(ord(plain_text[i]) + ord(key[j]) - 2 * ASCII_OFFSET)

        # Appends the character to the end of the cipher text string
        cipher_text = cipher_text + chr(new_char + ASCII_OFFSET)

    return cipher_text


def main(argv: list):
    '''
    main

    Reads in a keyword and plain text message to encrypt. Using the keyword,
    the plain text is first encrypted. Then the keyword is attempted to be
    found by performing a known-plain text attack with brute force. The
    runtime of the function and the series of operations that take place is
    timed and printed to the command line.

    Due to the fact that a keyword can be anything and is typically a word
    in the English dictionary, it can be difficult to get the exact keyword
    without knowledge of potential words. This knowledge is not implemented
    into the program but is possible if the keyword was compared against a
    dictionary.

    Command format:
        julia vigenere.jl [keyword] [plain text message]

    Parameters:
        argv - list of command arguments
    '''

    # Checks that there are exactly two command line arguments
    if len(argv) != 2:
        print('USAGE: python vigenere.py [keyword] [plain text message]')
        sys.exit(2)

    # Extracts the keyword
    keyword = argv[0]

    # Extracts the plain text message to be encrypted
    plain_text = argv[1]

    # Removes white spaces and converts the plain text to lower case, so that it
    # can esaily be encrypted.
    plain_text = plain_text.replace(' ', '')
    plain_text = plain_text.lower()
    keyword = keyword.lower()

    # Encrypts the plain text message using the encryption key
    cipher_text = encrypt(plain_text, keyword)

    # Overrides the timeit.tempate so that the return value of the brute_force
    # function is captured
    timeit.template = '''
def inner(_it, _timer{init}):
    {setup}
    _t0 = _timer()
    for _i in _it:
        retval = {stmt}
    _t1 = _timer()
    return _t1 - _t0, retval
'''

    # Simulate a known-plaintext attack by brute forcing the keyword
    print('Time to brute force the keyword:')

    # Times the run time of the brute force function
    t = timeit.Timer(functools.partial(decrypt, cipher_text, plain_text))
    result = t.timeit(1)
    print(result[0], 'seconds')

    if result[1] is None:
        print("Unable to find keyword")
    else:
        # Displays the keyword
        print('Found Keyword:')
        print(result[1])

main(sys.argv[1:])