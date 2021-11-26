# Hills cryptosystem
using LinearAlgebra
using DelimitedFiles

# Size of the N x N matrix
global const N = 2

# Integers modulo 26
global const NUM_LETTERS = 26

# Table of inverses mod 26, where the index is the element
# and the value is its multiplicative inverse. If the element
# doesn't have a multiplicative inverse (like 2) the value at
# the index is -1
global const INV_MOD_26 = [
    1, -1, 9, -1, 21, -1, 15, -1, 3, -1, 19, -1, -1, -1, 7, -1, 23, -1, 11, -1, 5 ,-1, 17, -1, 25
]

message = "TEST"

# M = zeros(Int8, SIZE, SIZE)
M = [
    27 31;
    19 52 
]

M = map((x) -> x % NUM_LETTERS , M)

function is_valid_key(K)
    valid = true

    # Gets a, b, c, d elements of the matrix
    a = K[1, 1]
    b = K[1, 2]
    c = K[2, 1]
    d = K[2, 2]

    # Calculates the determinant of the matrix
    v = mod(det(M), NUM_LETTERS)

    # Checks if the determinant is invertible in ℤ26
    if v == 0 || INV_MOD_26[Int(v)] == -1
        valid = false
    end

    return valid
end

function encrypt(plain_text, K)

    # Character to be added onto the end of the plaintext
    # if the message is not a multiple of N
    FILL_CHAR = "x"

    # Stores the enciphered text
    cipher_text = ""

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

    # Vector for storing N characters
    pt_vec = zeros(Int8, N)

    # Encrypts the message
    for i in 1:N:pt_len
        
        # Converts N characters of the plain text to
        # integers for the vector
        for j in 0:(N - 1)
            c = convert(Int8, plain_text[j + i]) - 96
            pt_vec[j + 1] = c
        end

        # Encrypts the plain text vector to cipher text
        cipher_vec = K * pt_vec

        # Modulos the cipher text vector be in ℤ26
        cipher_vec = map((x) -> mod(x, NUM_LETTERS), cipher_vec) 
        
        # Converts the cipher text vector to characters
        # and appends them to the cipher text string
        for j in 1:N
            cipher_char = Char(cipher_vec[j] + 96)
            cipher_text = cipher_text * string(cipher_char)
        end
    end

    return cipher_text
end

function invert(M)

    # Computes the determinant
    determinant = mod(det(M), NUM_LETTERS)

    if determinant == 0
        return nothing
    end

    # Looks up the multiplicative inverse of the determinant
    mul_inv = INV_MOD_26[Int(determinant)]

    if mul_inv == -1
        return nothing
    end

    # Extracts the elements of the matrix
    a = M[1, 1]
    b = M[1, 2]
    c = M[2, 1]
    d = M[2, 2]

    # Creates a new matrix to multiply the inverse with
    V = zeros(Int8, N, N)
    V[1, 1] = d
    V[1, 2] = -b
    V[2, 1] = -c
    V[2, 2] = a 

    # Computes the inverse
    inv = mul_inv * V

    # Maps the matrix modulo 26
    inv = map((x) -> mod(x, NUM_LETTERS), inv)

    return inv
end

function decrypt(cipher_text, K)

    # Stores the enciphered text
    plain_text = ""

    ct_len = length(cipher_text)

    # Vector for storing N characters
    ct_vec = zeros(Int8, N)

    # decrypts the message
    for i in 1:N:ct_len
        
        # Converts N characters of the plain text to
        # integers for the vector
        for j in 0:(N - 1)
            c = convert(Int8, cipher_text[j + i]) - 96
            # print(c, "\n")
            ct_vec[j + 1] = c
        end

        # print(ct_vec)

        # Encrypts the plain text vector to cipher text
        plain_vec = K * ct_vec

        # print("K ", K, "\n")
        # print("cv ", ct_vec, "\n")
        # print("pv ", plain_vec, "\n")

        # Modulos the cipher text vector be in ℤ26
        plain_vec = map((x) -> mod(x, NUM_LETTERS), plain_vec) 
        
        # Converts the cipher text vector to characters
        # and appends them to the cipher text string
        for j in 1:N
            plain_char = Char(plain_vec[j] + 96)
            plain_text = plain_text * string(plain_char)
        end
    end

    return plain_text
end

function brute_force(cipher_text, M)

    F = zeros(N, N)
    count = 1

    for i in 0:NUM_LETTERS - 1
        for j in 0:NUM_LETTERS - 1
            for k in 0:NUM_LETTERS - 1
                for l in 0:NUM_LETTERS - 1
                    F[1, 1] = i
                    F[1, 2] = j
                    F[2, 1] = k
                    F[2, 2] = l

                    if is_valid_key(F)
                        # plain_text = decrypt(cipher_text, F)
                        # print(plain_text, "\n")
                        count += 1
                        if F == M
                            return F
                        end
                    end
                end
            end
        end
    end
end

# cipher = encrypt("kaivickers", M)
# brute_force(cipher, M)

function main(args)

    # https://stackoverflow.com/questions/44337529/parse-2d-array-in-julia?rq=1
    # https://docs.julialang.org/en/v1/stdlib/DelimitedFiles/
    a = readdlm(IOBuffer(args[1]), ',',Int,';' )
    i = args[2]
    # display(a)
    # display(i)

    cipher = encrypt(i, a)
    @time brute_force(cipher, a)
end

main(ARGS)


