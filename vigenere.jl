"""
CS 352 Final Project
Vignere Cryptosystem implemented in Julia

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
"""

using LinearAlgebra

# Global Constants:
# String containing all the lower case letters in the English alphabet
global const ALPHABET = "abcdefghijklmnopqrstuvwxyz"

# Number of letters in the English alphabet
global const NUM_LETTERS = 26

# ASCCI number of lowercase 'a' to start at 1
global const ASCII_OFFSET = 97

# Order of letters by decreasing frequency of appearance in a message
global const FREQ_ORDER = "etaoinshrdlcumwfgypbvkjxqz"

"""
analyze_frequency

Takes in a cipher text message and returns an array containing the
number of occurences for each character in the cipher text, where
the character corresponds to the index of the array.

Parameters:
    cipher_text - the encrypted message string

Returns:
    An array containing the number of occurences for each character
"""
function analyze_frequency(cipher_text)::Array

    # Initializes the frequency array to all zeros to
    # store the number of occurences of each letter
    frequency_array = zeros(NUM_LETTERS)

    ct_len = length(cipher_text)

    # Iterates through each character in the plain text and
    # increments the value of the frequency array of each
    # character it comes across
    for i in 1:ct_len

        # Extracts the character from the plain text
        char = cipher_text[i]
        
        # Checks if the char is exclusively a lowercase letter
        if occursin(char, ALPHABET)

            # Adds 1 to the corresponding spot of the character
            # in the frequenct array
            char = Int(char) - ASCII_OFFSET
            frequency_array[char + 1] += 1
        end     
    end

    return frequency_array
end

"""
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
"""
function calculate_IC(cipher_text::String)::Float16

    cipher_text = replace(cipher_text, " " => "")
    cipher_text = lowercase(cipher_text)
    ct_len = length(cipher_text)

    # Computes the frequency array of the plain text
    frequency_array = analyze_frequency(cipher_text)

    sum = 0

    # Sums the numerator of the formula
    for n in frequency_array
        sum += (n * (n - 1))
    end

    # If the plain text is empty the IC value is 0,
    # otherwise, it divides the summation by the 
    # denominator of the formula
    if ct_len == 0
        return 0.0
    else
        ic = sum / (ct_len * (ct_len - 1))
    end

    return ic
end

"""
factors

Takes in a number and produces an array of all its existing factors.
Factors that are improbable key lengths are ignored, such as 1 and 2. 

Parameters:
    x - the number to factorize

Returns:
    An array of factors
"""
function factors(x)::Array

    # Stores the factors
    factors = []

    # Loops through all possible numbers up to x and
    # checks if the number is divisible by the index
    for i in 1:x

        # If the number is divisible, its added to the factors
        if x % i == 0 && i != 1 && i != 2
            push!(factors, i)
        end
    end

    return factors 
end

"""
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
"""
function kasiski_test(cipher_text::String)::Union{Array, Nothing}

    cipher_text = replace(cipher_text, " " => "")
    ct_len = length(cipher_text)

    # Initializes an empty dictionary for all the substrings of the plain text
    substring_occur = Dict{String, Int}()

    # Iterates through every possible substring of length 3 or greater
    # in the plain text and adds an entry to the substring_occur 
    # dictionary with the number of occurences
    for i in 1:ct_len
        for len in (i + 2):ct_len

            # Gets the substring
            substring = cipher_text[i:len]

            # Gets the number of occurences of the substring in the plain text
            occur = length(collect(eachmatch(Regex(substring), cipher_text)))
            
            # If there are more than two occurences of the substring,
            # it gets stored
            if occur >= 2
                substring_occur[substring] = occur
            end
        end
    end

    # Initializes an empty array of distance values between substring occurences
    distances = Int[]

    # Gets the substrings that have two or more occurences
    substrings = collect(keys(substring_occur))

    for substring in substrings

        # Gets a vector of all the substring indices
        indices = findall(substring, cipher_text)

        # Gets the length of all the index occurences
        indices_len = length(indices)

        # Iterates through each index pair and substracts the starting index
        # of the first occurene from the starting index of the next occurence
        for i in indices_len:-1:2
            
            # Calculates the distance
            dist = collect(indices[i])[1] - collect(indices[i - 1])[1]    
            
            # Adds the distance to the array of distances
            push!(distances, dist)
        end
    end

    # Gets the number of distane values
    num_distances = length(distances)

    # Initializes an empty set of greatest common divisors
    gcds = Set{Int}()

    # Calculates multiple r values by taking the gcd between each
    # distance. This could be implemented using merge sort to make
    # it faster.
    for i in 1:num_distances - 1
        for j in (i+1):(num_distances)

            # Calculates the value of r
            r = gcd(distances[i], distances[j])
            
            # If the r value is 1 or less, it gets ignored
            if r > 1

                # Adds the r value to the set of gcds
                push!(gcds, r)
            end
        end
        
        pf = factors(distances[i])
        gcds = union(gcds, pf)
        # gcds = union(gcds, f)

    end

    if num_distances > 0
        gcds = union(gcds, factors(distances[num_distances]))
    end

    # Sorts the gcds in ascending order
    gcds = sort(collect(gcds))

    # If gcds is empty, nothing is returned. This occurs when
    # the only r value is 1 that is calculated.
    if isempty(gcds)
        return nothing
    else
        return gcds
    end
end

"""
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
"""
function _IC_test(n::Int64, _IC::Float16)

    # Computes r, which is the length of the keyword or an approximation of it.
    r = 0.027 * n / (((n - 1) * _IC) - (0.038 * n) + 0.065)

    return r

end

"""
decrypts

Takes in a cipher text and keyword, and uses the keyword to decrpyt the
cipher text back to the original plain text by shifting each character
"backwards" using the corresponding value of the letter in the keyword.

Parameters:
    cipher_text - encrypted plain text using the Vigenere system
    keyword - the keyword used to encrypt the cipher text

Returns:
    The resulting deciphered plain text
"""
function decrypt(cipher_text, keyword)::String
    
    # Gets the length of the plain text and the keyword
    ct_length::Int8 = length(cipher_text)
    key_length::Int8 = length(keyword)

    # Stores the encrypted cipher text
    plain_text::String = ""

    # Iterates through each letter in the plain text and encrypts the letter
    # by shifting it the amount of the corresponding letter in the keyword
    for i in 0:ct_length - 1

        # Gets the index of the keyword
        j = i % key_length + 1

        # Gets the new character value from the shift
        new_char::Int8 = mod(Int(cipher_text[i + 1]) - Int(keyword[j]), NUM_LETTERS)

        # Appends the character to the end of the cipher text string
        plain_text = plain_text * Char(new_char + ASCII_OFFSET)
    end

    return plain_text
end

"""
brute_force

Attempts to decrypt a cipher text message by performing the IC and 
Kasiski tests to find a probable keylength. Using this probable
key length, the text is split up into columns that are equal to the
length of the probable key word length. The columns are then sorted
by frequency of each letter.

Parameters:
    cipher_text - encrypted plain text using the Vigenere system
    plain_text - the message string

Returns:
    The resulting keyword that is mapped onto the plaintext
"""
function brute_force(cipher_text::String, plain_text::String)::Union{String, Nothing}
    
    ct_length = length(cipher_text)

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
    # Otherwise, it finds the closest value to r from the
    # potential key lengths
    if key_lengths === nothing

        if r > 1
            # Converts r to an integer
            probable_lengths = floor(Int, r)
        else
            return nothing
        end
    else
        probable_lengths = key_lengths
    end

    found_key = nothing

    for probable_len in probable_lengths

        # Stores the keyword for this probable length
        found_key = ""

        # Initializes a Vector of Vectors of monoalphabetic schemes
        ma_columns = Vector{Vector{Char}}()

        # Intializes the monoalphabetic schemes
        for _ in 1:probable_len

            # Initializes the character vector
            char_vec = Vector{Char}()

            # Adds the character vector to the scheme
            push!(ma_columns, char_vec)

        end

        # Adds the characters of the cipher text to their respective 
        # monoalphabetic schemes
        for i in 0:ct_length - 1

            j = i % probable_len + 1
            
            push!(ma_columns[j], cipher_text[i + 1])
            
        end

        # The index of the cipher text and plain text
        k = 1

        # Loops through each character in the probable length
        for i in 1:probable_len

            # Extracts the column values
            col = ma_columns[i]
            col_len = length(col)

            # Performs frequency analysis on the column
            freq = analyze_frequency(col)

            # Sorts the column based on the frequency analysis
            if col_len < NUM_LETTERS
                perm = sortperm(freq[1:col_len])
            else
                perm = sortperm(freq[1:NUM_LETTERS])
            end
            
            sorted = col[perm]

            for j in 1:NUM_LETTERS

                # Creates the shift char from the first character of the sorted column
                # and the current character in the frequenct order
                sort_char = Int(sorted[1]) - ASCII_OFFSET
                f_char = Int(FREQ_ORDER[j]) - ASCII_OFFSET

                # Calculates the shift value between the sorted column and
                # frequency order of characters
                shift = mod((sort_char - f_char), NUM_LETTERS)

                # Gets the character of the shift value
                key_char = Char(shift + ASCII_OFFSET)

                # Decrypts the first letter of the cipher text using
                # the keywrod character
                decrypt_char = decrypt(cipher_text[k], key_char)

                # If the resulting decrypted character is the same as the plain text
                # character in the corresponding position, the keyword character is
                # added to the found key string
                if cmp(decrypt_char, string(plain_text[k])) == 0

                    found_key = found_key * key_char

                    # If the found key string is equal to the length of the cipher
                    # text, it returns the found key which shows the repetition
                    if length(found_key) == ct_length
                        return found_key
                    end
                    
                    # Increments k for the next character
                    k += 1
                end
            end
        end
    end

    # If the found key wasn't completely found, it returns whatever is present
    if length(found_key) > 0
        return found_key

     # None is returned if the brute force was unsuccessful
    else
        return nothing
    end
end

"""
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
"""
function encrypt(plain_text::String, keyword::String)::String

    # Gets the length of the plain text and the keyword
    pt_length::Int8 = length(plain_text)
    key_length::Int8 = length(keyword)

    # Stores the encrypted cipher text
    cipher_text::String = ""

    # Iterates through each letter in the plain text and encrypts the letter
    # by shifting it the amount of the corresponding letter in the keyword
    for i in 0:pt_length - 1

        # Gets the index of the keyword
        j = i % key_length + 1

        # Gets the new character value from the shift
        new_char::Int8 = mod(Int(plain_text[i + 1]) + Int(keyword[j]) - 2 * ASCII_OFFSET, NUM_LETTERS)

        # Appends the character to the end of the cipher text string
        cipher_text = cipher_text * Char(new_char + ASCII_OFFSET)
    end

    return cipher_text
end

"""
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
"""
function main(argv::Array)

    # Checks that there are exactly two command line arguments
    if length(argv) != 2
        print("USAGE: julia vigenere.jl [keyword] [plain text message]")
        exit(0)
    end

    # Extracts the keyword
    keyword = argv[1]

    # Extracts the plain text message to be encrypted
    plain_text = argv[2]

    # Removes white spaces and converts the plain text to lower case, so that it
    # can esaily be encrypted.
    plain_text = replace(plain_text, " " => "")
    plain_text = lowercase(plain_text)
    keyword = lowercase(keyword)
    
    # Encrypts the plain text message using the keyword
    cipher_text = encrypt(plain_text, keyword)

    # Simulate a known-plaintext attack by brute forcing the keyword
    print("Time to brute force the keyword:\n")

    # Times the run time of the brute force function
    decrypt_keyword = @time brute_force(cipher_text, plain_text)

    # Prints the key that was found or a failure message
    if decrypt_keyword === nothing
        print("Unable to find keyword")
    else
        # Displays the keyword
        print("Found Keyword:\n")
        display(decrypt_keyword)
    end
end

main(ARGS)