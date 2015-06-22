from math import log
from collections import Counter
from datetime import date

from pyparsing import Word, ParseException, Optional, lineEnd

import string

lower = string.ascii_lowercase
upper = string.ascii_uppercase
letters = string.ascii_letters
digits = string.digits
hexdigits = string.hexdigits
leetdigits = "01345"
leetletters = "oieas"
leet = lower + leetdigits
symbols = ",.?!@#$%^&*-+~_"
allchars = string.printable

# twp-digit years from the last 32 years
currentYear = date.today().year
twoDigitYears = {"{:2d}".format(year) for year in range(currentYear - 31, currentYear + 1)}
# four-digit years from the last 64 years
fourDigitYears = {str(year) for year in range(currentYear - 63, currentYear + 1)}
# all dates of the form MMDD, including 0229
monthLengths = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
dates = {"{:2d}{:2d}".format(month, day) for month in range(1,13) for day in range(1, monthLengths[month - 1] + 1)}

leetToAscii = {"0": "o",
               "1": "i",
               "3": "e",
               "4": "a",
               "5": "s"}

leetPattern = Word(leet).setResultsName("leet")
numbersPattern = Word(digits).setResultsName("numbers")
symbolsPattern = Word(symbols).setResultsName("symbols")
remainderPattern = Optional(Word(allchars)).setResultsName("remainder") + lineEnd
patterns = [[leetPattern + remainderPattern],
            [numbersPattern + remainderPattern],
            [leetPattern + numbersPattern + remainderPattern,
             leetPattern + symbolsPattern + remainderPattern],
            [leetPattern + numbersPattern + symbolsPattern + remainderPattern,
             leetPattern + symbolsPattern + numbersPattern + remainderPattern,
             numbersPattern + symbolsPattern + remainderPattern,
             symbolsPattern + numbersPattern + remainderPattern]
           ]

def deLeet(string):
    result = ""

    for char in string:
        if char in leetToAscii:
            result += leetToAscii[char]
        else:
            result += char

    return result

def randomStrength(password):
    """
    Strength of a truly random password, based on length and charset.
    """
    charsets = [lower, upper, letters, digits, hexdigits, lower + digits, upper + digits, letters + digits,
                lower + symbols, upper + symbols, letters + symbols, digits + symbols, hexdigits + symbols,
                lower + digits + symbols, upper + digits + symbols, letters + digits + symbols]

    lowestCharsetBonus = 6    # base64 bonus
    for charset in charsets:
        inCharset = all([char in charset for char in password])

        if inCharset:
            lowestCharsetBonus = min(lowestCharsetBonus, log(len(charset), 2))

    bonus = lowestCharsetBonus * len(password)

    # handle really small subsets of charsets
    distinctChars = len(set(password))
    if distinctChars == 1:
        bonus = min(bonus, lowestCharsetBonus + int(log(len(password), 2)) + 1)
    elif distinctChars == 2:
        bonus = min(bonus, 2 * lowestCharsetBonus + len(password)) + int(log(len(password), 2))
    elif distinctChars == 3:
        bonus = min(bonus, 3 * lowestCharsetBonus + log(3, 2) * len(password) + int(log(len(password), 2))  - 1)

    return int(bonus)

class PatternStrengthTester(object):
    """
    Defines the strength(password) method which returns the number of bits
    of entropy a password has, relative to the given wordlists and patterns.
    """
    def __init__(self, wordlists):
        """
        Args:
            wordlists ([[str]]): words from which passwords are taken, seperated
                                 into different categories.
        """
        self.wordlists = sorted([(set(wordlist), log(len(wordlist), 2)) for wordlist in wordlists], key=lambda (x,y): y)

    @staticmethod
    def capitalBonus(string):
        lowercase = 0
        uppercase = 0
        for char in string:
            if char.islower():
                lowercase += 1
            elif char.isupper():
                uppercase += 1

        if uppercase == 0:
            return 0
        elif uppercase == 1 and string[0].isupper():
            return 1

        return lowercase + uppercase

    @staticmethod
    def numberBonus(string):
        if string == "1":    # always first guess
            return 0
        if string in twoDigitYears:
            return 5
        if string in fourDigitYears:
            return 6
        if string in dates:
            return 9

        return 10 * len(string) / 3

    @staticmethod
    def symbolBonus(string):
        if string == "!":    # always first guess
            return 0
        if string == "!" * len(string):
            return len(string) - 1

        return 4 * len(string)

    def leetBonus(self, string):
        leetchars = 0
        leetable = 0
        for char in string:
            if char in leetdigits:
                leetchars += 1
            if char in leetletters:
                leetable += 1

        wordscore = self.wordlistBonus(deLeet(string))

        if leetchars == 0:
            return wordscore
        elif wordscore:
            return leetable + leetchars + wordscore
        else:
            return None

    def wordBonus(self, string):
        result = 10000

        for kind in self.wordlists:
            wordset, bonus = kind

            if string in wordset:
                result = min(result, bonus)
            elif string != "" and string[-1] == "s" and string[:-1] in wordset:
                result = min(result, bonus)

        if result == 10000:
            return None

        return result

    def wordlistBonus(self, string):
        """
        Return the lowest sum of of word bonuses obtained by breaking a string
        into a list of words.
        """
        if string == "":
            return 0

        results = [None] * len(string)    # results[i] = wordsBonus(string[:i])

        for i in range(len(string)):
            results[i] = self.wordBonus(string[:i + 1])

            for j in range(i):
                sliceBonus = self.wordBonus(string[j + 1:i + 1])

                if results[j] != None and sliceBonus != None:
                    if results[i] != None:
                        results[i] = min(results[i], results[j] + sliceBonus)
                    else:
                        results[i] = results[j] + sliceBonus

        return results[len(string) - 1]

    def remainderBonus(self, string):
        return 1 + self.strength(string)

    def strength(self, password):
        """
        Returns the number of bits of entropy in a password, from the perspective of
        an attacker using the passed wordlists and built-in patterns to build a dictionary.
        """
        bonusFunctions = {
            "words": self.wordlistBonus,
            "numbers": self.numberBonus,
            "symbols": self.symbolBonus,
            "leet": self.leetBonus,
            "remainder": self.remainderBonus,
        }
        entropy = 10000

        for i in range(len(patterns)):
            for pattern in patterns[i]:
                try:
                    match = pattern.parseString(password.lower()).asDict()
                except ParseException:
                    continue

                possibleMatches = [match]
                if "leet" in match:
                    # handle issue of greedyness eating trailing numbers
                    while match["leet"] != "" and match["leet"][-1] in digits:
                        match = match.copy()

                        if "numbers" in match:
                            match["numbers"] = match["leet"][-1] + match["numbers"]
                        else:
                            match["numbers"] = match["leet"][-1]
                        match["leet"] = match["leet"][:-1]

                        possibleMatches.append(match)

                for possibleMatch in possibleMatches:
                    matchEntropy = i + self.capitalBonus(password)

                    for elem in possibleMatch:
                        bonus = bonusFunctions[elem](possibleMatch[elem])

                        if bonus != None:
                            matchEntropy += bonus
                        else:
                            matchEntropy = None
                            break

                    if matchEntropy and matchEntropy < entropy:
                        entropy = matchEntropy

        return int(min(entropy, randomStrength(password)))
