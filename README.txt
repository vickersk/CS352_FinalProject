###############################################################################################
CS 352 Final Project

GitHub Link: https://github.com/vickersk/CS352_FinalProject

Author: Kai Vickers
Last Modified: 12/3/2021
###############################################################################################
Overview:

The purpose of this project was to compare the performance of the Julia and Python programming 
languages by implementing the Hills and Vigenere cryptosystems in both languages, and then 
measuring the time it takes for both languages to find a decryption key through brute force. 
This is accomplished by simulating a known-plain text attack were a given plain text and cipher
text correspondence is known and can be used to solve for the encryption/decryption key. 

The implementation of the two cryptosystems, specifically the Hills system that involves matrix 
multiplication, and the use of brute force was intended to demonstrate the main feature of 
Julia, which is its usage for scientific and numerical computing. Scientific and numerical 
computing often requires lots of iterations and can involve taxing operations, which is why 
Julia is designed to have a high performance that is comparable to statically typed languages 
like C or Fortran. 

While Python isn’t necessarily designed directly for scientific and numerical computing 
purposes, it’s wide support and ease of use has made it a popular programming language for 
working with data, such as for data science and machine learning applications. The goal of this 
project was to test the effectiveness and speed of Julia by comparing it to a language that has 
similar features and might be utilized for similar applications. 

###############################################################################################
How to compile and run the program:

To compile and run the programs in the project, python and julia are both required. 
Additionally, the python library, numpy, is required for running the program, hills.py.

Each of the programs can be run as follows:
 - hills.jl

    julia hills.jl [matrix key] [plain text message]

    Example execution:
    julia hills.jl "1,7;0,25" "hello world"

 - hills.py

    python hills.py [matrix key] [plain text message]

    Example execution: 
    python hills.py "[[1,7],[0,25]]" "hello world"

 - vigenere.jl

    julia vigenere.jl [keyword] [plain text message]

    Example execution:
    julia vigenere.jl "cheese" "blue blue blue blue"

 - vigenere.py

    python vigenere.py [keyword] [plain text message]

    Example execution:
    python vigenere.py "cheese" "blue blue blue blue"

Matrix key input format:
 - hills.jl
    
    "e,e;e,e"

    Each row contains two integer values seperated by ',' that are between 0 and 25. A ';' is
    used to seperate the two rows. The input is also surrounded with "".

    Example matrix input:
    "1,7;0,25"

- hills.py

    "[[e,e],[e,e]]"

    Each row contains two integer values seperated by ',' that are between 0 and 25. Each row is
    surrounded in [] and are seperated by ','. Both rows are surrounded by outer []. The input is
    also incased with "".

    Example matrix input:
    "[[1,7],[0,25]]"

Keyword and plain text input:
The keyword input must be a single word that only contains lower case English letters.
The plain text input can be a sentence containing whitespace but must also only contain lower
case English letters.
    
###############################################################################################
Additional Information:

The Vigenre cryptosystem programs are not guaranteed to brute force the  keyword based on
these implementations, which soley rely on statistical calculations for finding probable key 
lengths and using those key lengths and the frequency of letters in the cipher text to find the
potential keyword.

A brute force attack could be perfromed that uses a dictionary to iterate and check each word
until one produces decrypted text that matches the plain text. I decided to go with this 
approach since it seems more interesting, but a potential enhancement to the project could be
implementing the dictionary search to aid the current methodology.

###############################################################################################
