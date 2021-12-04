'''
CS 352 Final Project
Hills Cryptosystem implemented in Python

Description:
In simplified terms, the Hill’s system encrypts a portion of plaintext that 
is length N using an invertible N × N matrix. Using a letter correspondence, 
where each letter in the English alphabet corresponds to an integer up to 26 
(a = 0, b = 1, etc.), the key matrix is multiplied with the plaintext block 
as a vector to produce the encrypted ciphertext block. This encryption process 
is repeated on each block in the message until the message is fully encrypted. 
To decrypt the ciphertext, the same method is applied but instead using the 
inverse of the key matrix.

Example inputs can be found in hills_python_cases.txt in the test_cases folder.

Author: Kai Vickers
Last Modified: 12/1/2021
'''

import sys
import json
import timeit, functools
import numpy as np

# Global Constants:
# Size of the N x N matrix
N = 2

# Number of characters in the English alphabet
NUM_LETTERS = 26

# ASCCI number of lowercase 'a' to start at 1
ASCII_OFFSET = 97

# Range for the values of the elements in a matrix
MIN_BOUND = 0
MAX_BOUND = 25

# Table of inverses mod 26, where the index is the element
# and the value is its multiplicative inverse. If the element
# doesn't have a multiplicative inverse (like 2) the value at
# the index is -1
INV_MOD_26 = [
    -1, 1, -1, 9, -1, 21, -1, 15, -1, 3, -1, 19, -1, -1, -1, 7, -1, 23, -1, 11, -1, 5 ,-1, 17, -1, 25
]

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

def is_valid_key(K: np.ndarray) -> bool:
    '''
    is_valid_key

    Checks if a key is a valid key for performing encryption and decryption
    on a plain text / cipher text correspondence. A key is valid if it has
    an inverse in the integers modulo 26, which means that the determinant of
    the matrix must be a unit in the ring. It aso checks if the values of the
    matrix are between 0 and 25. If the matrix is valid, True is returned. False
    is returned otherwise.

    Parameters:
        K - the matrix key to check if its valid

    Returns:
        True if the matrix is valid, False otherwise.
    '''

    valid = True

    # Iteratres through each element in the key matrix in checks
    # if its within the proper bounds
    for row in K:
        for cell in row:
            if cell < MIN_BOUND or cell > MAX_BOUND:
                return False

    # Calculates the determinant o the matrix
    v = int(round(np.linalg.det(K), 0)) % NUM_LETTERS

    # Checks if the determinant is invertible in ℤ26
    if v == 0 or INV_MOD_26[v] == -1:
        valid = False
    
    return valid

def extend_text(plain_text: str) -> str:
    '''
    extend_text

    If the plain text is not a multiple of N, then it adds the
    character 'x' onto the end to make it encryptable. 

    Parameters:
        plain_text - message string to be encrypted

    Returns:
        The resulting plain text with the added character
    '''

    # Character to be added onto the end of the plaintext
    # if the message is not a multiple of N
    FILL_CHAR = "x"

    pt_len = len(plain_text)

    # Number of filler characters needed
    fill_amount = pt_len % N

    # Adds axtra characters onto the end of the string
    # if the length of the message isn't a multiple of N
    if fill_amount != 0:

        # Creates a string of filler characters that is the
        # length of the fill amount
        filler = FILL_CHAR * fill_amount

        # Appends the extra characters
        plain_text = plain_text + filler

    return plain_text


def encrypt(plain_text: str, K: np.ndarray) -> str:
    '''
    encrypt

    Takes in a plain text and encryption key, and using the key encrypts
    the plain text to the corresponding cipher text. The resulting plain 
    text will appear as random characters.

    For encryption to work properly, the message length needs to be a
    multiple of the matrix size, which in this case is 2. If the message
    is an odd length an 'x' is added onto the end.

    Parameters:
        plain_text - message string to be encrypted
        K - the encryption key for encrypting the cipher text

    Returns:
        The resulting enciphered cipher text
    '''

    # Stores the encrypted cipher text
    cipher_text = ''

    # Adds additional characters if the plain text is not a multiple of N
    plain_text = extend_text(plain_text)

    pt_len = len(plain_text)
        
    # Vector for storing N characters
    pt_vec = np.zeros((N, 1))

    # Encrypts the message
    for i in range(0, pt_len, N):
        
        # Converts N characters of the plain text to
        # integers for the vector
        for j in range(0, N):
            c = ord(plain_text[j + i]) - 97
            pt_vec[j] = c

        # Encrypts the plain text vector to cipher text
        cipher_vec = np.dot(K, pt_vec)

        # Modulos the cipher text vector be in ℤ26
        cipher_vec = mod_26(cipher_vec)

        # Converts the cipher text vector to characters
        # and appends them to the cipher text string
        for j in range(0, N):
            cipher_char = chr(int(cipher_vec[j]) + 97)
            cipher_text = cipher_text + str(cipher_char)
        
    return cipher_text

def invert(M):
    '''
    invert

    Takes in a matrix and inverts it within the integers modulo 26.
    It first computes the determinant of the matrix within the integers
    modulo 26. If the determinant is 0 or if the determinant has no
    multiplicative inverse, nothing is returned. Otherwise, it 
    computes the matrix as follows:

        inv(M) = (ad - bc)^-1 * [d, -b; -c, a]

    Parameters:
        M - the matrix to take the inverse of

    Returns:
        The inverse of the matrix if it exists, nothing otherwise.
    '''

    # Computes the determinant
    determinant = np.linalg.det(M) % NUM_LETTERS

    # Returns nothing if the matrix is 0
    if determinant == 0:
        return None

    # Looks up the multiplicative inverse of the determinant
    mul_inv = INV_MOD_26[int(round(determinant, 0))]

    # Reutrns nothing if the determinant doesn't have a
    # multiplicative inverse
    if mul_inv == -1:
        return None

    # Extracts the elements of the matrix
    a = M[0, 0]
    b = M[0, 1]
    c = M[1, 0]
    d = M[1, 1]

    # Creates a new matrix to multiply the inverse with
    V = np.zeros((N, N), dtype=int)
    V[0, 0] = d
    V[0, 1] = -b
    V[1, 0] = -c
    V[1, 1] = a 

    # Computes the inverse
    inv = mul_inv * V

    # Maps the inverse matrix to modulo 26
    inv = mod_26(inv)

    return inv

def decrypt(cipher_text: str, K: np.ndarray) -> str:
    '''
    decrypt

    Takes in a cipher text and decryption key, and using the key decrypts
    the cipher text to the corresponding plain text. If the key is not
    the correct deciphering key, the resulting plain text will appear as
    random characters.

    Parameters:
        cipher_text - encrypted plain text using the Hill's system
        K - the decryption key for deciphering the cipher text

    Returns:
        The resulting deciphered plain text
    '''

    # Stores the deciphered text
    plain_text = ""

    ct_len = len(cipher_text)

    # Vector for storing N characters
    ct_vec = np.zeros(N)

    # Decrypts the message
    for i in range(0, ct_len, N):
        
        # Converts N characters of the cipher text to
        # integers for the vector
        for j in range(0, N):
            c = ord(cipher_text[j + i]) - ASCII_OFFSET
            ct_vec[j] = c

        # Decrypts the cipher text vector to plain text
        plain_vec = K @ ct_vec

        # Modulos the plain text vector be in ℤ26
        plain_vec = mod_26(plain_vec)
        
        # Converts the plain text vector to characters
        # and appends them to the plain text string
        for j in range(0, N):
            plain_char = chr(int(plain_vec[j]) + ASCII_OFFSET)
            plain_text = plain_text + str(plain_char)
        
    return plain_text


def brute_force(cipher_text: str, plain_text: str) -> np.ndarray:
    '''
    brute_force

    Determines the deciphering key of the cryptosystem by simulating a
    known-plaintext attack using brute force. The function iterates through
    every key combination and checks if it is a valid key. If so, it decrypts
    the cipher text using the current key and compares it to the plain text. 

    Parameters:
        cipher_text - encrypted plain text using the Hill's system
        plain_text - plain text message that corresponds to the cipher text

    Returns:
        The decryption key. If no decryption key is found, then None.
    '''
    
    # Initializes the key matrix to all zeros
    K = np.zeros((N, N), dtype=int)

    # Iterates through every possible N x N matrix, N = 2
    for i in range(0, NUM_LETTERS):
        for j in range(0, NUM_LETTERS):
            for k in range(0, NUM_LETTERS):
                for l in range(0, NUM_LETTERS):

                    # Sets the values of the matrix
                    K[0, 0] = i
                    K[0, 1] = j
                    K[1, 0] = k
                    K[1, 1] = l

                    # Checks if the key is valid
                    if is_valid_key(K):

                        # Decrypts the cipher text using the key
                        decrypted_text = decrypt(cipher_text, K)
                        
                        # Returns the key if the decrypted text and plain text
                        # are the same
                        if decrypted_text == plain_text:
                            return K

    # None is returned if no key is found
    return None

def main(argv: list):
    '''
    main

    Reads the input file for the two finite automata and
    creates an NFA for the concatentation of the two languages.
    The output is then printed to the terminal and written to
    the output file.

    Reads in a encryption key matrix and plain text message to encrypt.
    If the key is valid, the plain text message is encrypted using the
    specified key. After which a known-plaintext attack is performed to
    brute force the decryption key. The runtime of the function and the
    series of operations that takes place is timed and printed to the 
    command line.

    Command format:
        python hills.py [matrix key] [plain text message]

    Input Matrix format:
        "[[e,e],[e,e]]"

    Parameters:
        argv - list of command arguments
    '''

    if len(argv) != 2:
        print('USAGE: python hills.py [matrix key] [plain text message]')
        sys.exit(2)

    try:
        # Stores the input and output files
        key = np.array(json.loads(argv[0]))

        if not is_valid_key(key):
            print("ERROR: Encryption key is not valid. Please enter a valid encryption key")
            sys.exit(0)

    except Exception:
        print("ERROR: Input not in the proper format. Please enter a matrix key followed by a plain text message")
        sys.exit(2)

    # Extracts the plain text message to be encrypted
    plain_text = argv[1]

    # Removes white spaces and converts the plain text to lower case, so that it
    # can esaily be encrypted.
    plain_text = plain_text.replace(' ', '')
    plain_text = plain_text.lower()

    # Encrypts the plain text message using the encryption key
    cipher_text = encrypt(plain_text, key)

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

    # Simulate a known-plaintext attack by brute forcing the decryption key
    print("Time to brute force the decryption key:")
    
    # Extends the message if its not a multiple of N
    plain_text = extend_text(plain_text)

    # Times the run time of the brute force function
    t = timeit.Timer(functools.partial(brute_force, cipher_text, plain_text))
    result = t.timeit(1)
    print(result[0], 'seconds')

    # Displays the decryption and encryption key, the latter of which is found
    # by inverting the decryption key
    print("Found Decryption Key:")
    decrypt_key = result[1]
    print(decrypt_key)

    if decrypt_key is not None:
       encrypt_key = invert(decrypt_key)
       print("Found Encryption Key:")
       print(encrypt_key)

main(sys.argv[1:])