"""
CS 352 Final Project
Hills Cryptosystem implemented in Julia

Description:
In simplified terms, the Hill’s system encrypts a portion of plaintext that 
is length N using an invertible N × N matrix. Using a letter correspondence, 
where each letter in the English alphabet corresponds to an integer up to 26 
(a = 0, b = 1, etc.), the key matrix is multiplied with the plaintext block 
as a vector to produce the encrypted ciphertext block. This encryption process 
is repeated on each block in the message until the message is fully encrypted. 
To decrypt the ciphertext, the same method is applied but instead using the 
inverse of the key matrix.

Example inputs can be found in hills_julia_cases.txt in the test_cases folder.

Author: Kai Vickers
Last Modified: 12/2/2021
"""

using LinearAlgebra
using DelimitedFiles

# Global Constants:
# Size of the N x N matrix
global const N = 2

# Integers modulo 26
global const NUM_LETTERS = 26

# ASCCI number of lowercase 'a' to start at 1
global const ASCII_OFFSET = 97

# Range for the values of the elements in a matrix
global const MIN_BOUND = 0
global const MAX_BOUND = 25

# Table of inverses mod 26, where the index is the element
# and the value is its multiplicative inverse. If the element
# doesn't have a multiplicative inverse (like 2) the value at
# the index is -1
global const INV_MOD_26 = [
    1, -1, 9, -1, 21, -1, 15, -1, 3, -1, 19, -1, -1, -1, 7, -1, 23, -1, 11, -1, 5 ,-1, 17, -1, 25
]

"""
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
"""
function is_valid_key(K::Matrix)::Bool

    valid::Bool = true

    # Iteratres through each element in the key matrix in checks
    # if its within the proper bounds
    for e in eachindex(K)
        if K[e] < MIN_BOUND || K[e] > MAX_BOUND
            return false
        end
    end

    # Calculates the determinant of the matrix.
    # Rounds the determinant to account for Float64 conversion
    # during LU factorization.
    v::Int8 = mod(round(Int16, det(K)), NUM_LETTERS)

    # Checks if the determinant is invertible in ℤ26
    if v == 0 || INV_MOD_26[v] == -1
        valid = false
    end

    return valid
end

"""
extend_text

If the plain text is not a multiple of N, then it adds the
character 'x' onto the end to make it encryptable. 

Parameters:
    plain_text - message string to be encrypted

Returns:
    The resulting plain text with the added character
"""
function extend_text(plain_text::String)::String

    # Character to be added onto the end of the plaintext
    # if the message is not a multiple of N
    FILL_CHAR = "x"

    pt_len = length(plain_text)

    # Number of filler characters needed
    fill_amount = mod(pt_len, N)

    # Adds axtra characters onto the end of the string
    # if the length of the message isn't a multiple of N
    if fill_amount != 0

        # Creates a string of filler characters that is the
        # length of the fill amount
        filler = FILL_CHAR ^ fill_amount

        # Appends the extra characters
        plain_text = plain_text * filler
        
    end

    return plain_text

end

"""
encrypt

Takes in a plain text and encryption key, and using the key encrypts
the plain text to the corresponding cipher text. The resulting plain 
text will appear as random characters.

For encryption to work properly, the message length needs to be a
multiple of the matrix size, which in this case is 2. If the message
is an odd length an 'x' is added onto the end.

Parameters:
    plain_text - message string to be encrypted
    K - the encryption key for encrypting the plain text

Returns:
    The resulting enciphered cipher text
"""
function encrypt(plain_text::String, K::Matrix)::String

    # Stores the encrypted cipher text
    cipher_text::String = ""

    # Adds additional characters if the plain text is not a multiple of N
    plain_text = extend_text(plain_text)

    pt_len::Int8 = length(plain_text)

    # Vector for storing N characters
    pt_vec::Vector{Int8} = zeros(Int8, N)

    # Encrypts the message
    for i in 1:N:pt_len
        
        # Converts N characters of the plain text to
        # integers for the vector
        for j in 0:(N - 1)
            c::Int8 = convert(Int8, plain_text[j + i]) - ASCII_OFFSET 
            pt_vec[j + 1] = c
        end

        # Encrypts the plain text vector to cipher text
        cipher_vec::Vector{Float64} = K * pt_vec

        # Modulos the cipher text vector be in ℤ26
        cipher_vec = map((x) -> mod(x, NUM_LETTERS), cipher_vec) 
        
        # Converts the cipher text vector to characters
        # and appends them to the cipher text string
        for j in 1:N
            cipher_char::Char = Char(cipher_vec[j] + ASCII_OFFSET)
            cipher_text = cipher_text * string(cipher_char)
        end
    end

    return cipher_text
end

"""
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
"""
function invert(M::Matrix)::Matrix

    # Computes the determinant of the matrix
    determinant = mod(det(M), NUM_LETTERS)

    # Returns nothing if the matrix is 0
    if determinant == 0
        return nothing
    end

    # Looks up the multiplicative inverse of the determinant
    mul_inv = INV_MOD_26[Int(determinant)]

    # Reutrns nothing if the determinant doesn't have a
    # multiplicative inverse
    if mul_inv == -1
        return nothing
    end

    # Extracts the elements of the matrix
    a = M[1, 1]
    b = M[1, 2]
    c = M[2, 1]
    d = M[2, 2]

    # Creates a new matrix to multiply the multiplicative inverse of
    # the determinant with to get the inverse
    V = zeros(Int8, N, N)
    V[1, 1] = d
    V[1, 2] = -b
    V[2, 1] = -c
    V[2, 2] = a 

    # Computes the inverse
    inv = mul_inv * V

    # Maps the inverse matrix to modulo 26
    inv = map((x) -> mod(x, NUM_LETTERS), inv)

    return inv
end

"""
decrypt

Takes in a cipher text and decryption key, and using the ky decrypts
the cipher text to the corresponding plain text. If the key is not
the correct deciphering key, the resulting plain text will appear as
random characters.

Parameters:
    cipher_text - encrypted plain text using the Hill's system
    K - the decryption key for deciphering the cipher text

Returns:
    The resulting deciphered plain text
"""
function decrypt(cipher_text::String, K::Matrix)::String

    # Stores the deciphered text
    plain_text::String = ""

    ct_len::Int8 = length(cipher_text)

    # Vector for storing N characters
    ct_vec::Vector{Int8} = zeros(Int8, N)

    # Decrypts the message
    for i in 1:N:ct_len
        
        # Converts N characters of the cipher text to
        # integers for the vector
        for j in 0:(N - 1)
            c::Int8 = convert(Int8, cipher_text[j + i]) - ASCII_OFFSET
            ct_vec[j + 1] = c
        end

        # Decrypts the cipher text vector to plain text
        plain_vec::Vector{Float64} = K * ct_vec

        # Modulos the plain text vector be in ℤ26
        plain_vec = map(x -> mod(x, NUM_LETTERS), plain_vec) 
        
        # Converts the plain text vector to characters
        # and appends them to the plain text string
        for j in 1:N
            plain_char::Char = Char(plain_vec[j] + ASCII_OFFSET)
            plain_text = plain_text * string(plain_char)
        end
    end

    return plain_text
end

"""
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
"""
function brute_force(cipher_text::String, plain_text::String)::Union{Matrix{Int8}, Nothing}

    # Initializes the key matrix to all zeros
    K::Matrix = zeros(N, N)

    # Iterates through every possible N x N matrix, N = 2
    for i in 0:NUM_LETTERS - 1
        for j in 0:NUM_LETTERS - 1
            for k in 0:NUM_LETTERS - 1
                for l in 0:NUM_LETTERS - 1

                    # Sets the values of the matrix
                    K[1, 1] = i
                    K[1, 2] = j
                    K[2, 1] = k
                    K[2, 2] = l

                    # Checks if the key is valid
                    if is_valid_key(K)

                        # Decrypts the cipher text using the key
                        decrypted_text = decrypt(cipher_text, K)

                        # Returns the key if the decrypted text and plain text
                        # are the same
                        if decrypted_text == plain_text 
                            return trunc.(Int8, K)
                        end
                    end
                end
            end
        end
    end

    # None is returned if no key is found
    return nothing
end

"""
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
    julia hills.jl [matrix key] [plain text message]

Input Matrix format:
    "e,e;e,e"

Parameters:
    argv - list of command arguments
"""
function main(argv::Array)

    # Checks that there are exactly two command line arguments
    if length(argv) != 2
        print("USAGE: julia hills.jl [matrix key] [plain text message]")
        exit(0)
    end

    key = nothing

    # Tries to read the first argument as a matrix. If an exception is raised,
    # an error message is displayed
    try
        # Extracts the first argument as the encryption key
        key = readdlm(IOBuffer(argv[1]), ',',Int,';' )

        # Checks that the encryption key is valid. If not, an error is displayed
        if !is_valid_key(key)
            print("ERROR: Encryption key is not valid. Please enter a valid encryption key")
            exit(0)
        end

    # Prints an error message if an exception occurs
    catch e
        print("ERROR: Input not in the proper format. Please enter a matrix key followed by a plain text message")
        exit(0)
    end

    # Extracts the plain text message to be encrypted
    plain_text = argv[2]

    # Removes white spaces and converts the plain text to lower case, so that it
    # can esaily be encrypted.
    plain_text = replace(plain_text, " " => "")
    plain_text = lowercase(plain_text)
    
    # Encrypts the plain text message using the encryption key
    cipher_text = encrypt(plain_text, key)

    # Simulate a known-plaintext attack by brute forcing the decryption key
    print("Time to brute force the decryption key:\n")

    # Extends the message if its not a multiple of N
    plain_text = extend_text(plain_text)

    # Times the run time of the brute force function
    decrypt_key = @time brute_force(cipher_text, plain_text)

    # Displays the decryption and encryption key, the latter of which is found
    # by inverting the decryption key
    print("Found Decryption Key:\n")
    display(decrypt_key)

    if decrypt_key !== nothing
        encrypt_key = invert(decrypt_key)
        print("\nFound Encryption Key:\n")
        display(encrypt_key)
    end

end

main(ARGS)


