from django.core.exceptions import ValidationError
from django.utils.translation import ugettext as _
from django.utils._os import upath
from django.template.loader import render_to_string

from Crypto.Random.random import sample

from math import log
from difflib import SequenceMatcher

from .password_strength import PatternStrengthTester

import os
import gzip

class CommonPatternValidator(object):
    """
    Estimates the entropy of a password against a sophisticated attack which exploits
    common password patterns in combination with various wordlists.
    If the password entropy is below the set threshold, a ValidationError is raised.
    """
    DEFAULT_WORDLIST_DIR = os.path.join(
        os.path.dirname(os.path.realpath(upath(__file__))), 'wordlists'
    )

    DEFAULT_EXAMPLE_WORDS_FILE = os.path.join(
        os.path.dirname(os.path.realpath(upath(__file__))), 'example_words.txt'
    )

    MAX_EXAMPLE_SIMILARITY = 0.5

    def __init__(self, min_entropy=25, wordlist_dir=DEFAULT_WORDLIST_DIR, 
            example_words_file=DEFAULT_EXAMPLE_WORDS_FILE, use_cached_example=True):
        """
        Args:
            min_entropy (Optional(int)): The minimum number of bits of entropy a password must have.
            wordlist_dir (Optional(string)): Path to the directory of wordlists. Each 
                wordlist must be a newline-separated list of words, either as a text file
                or a gzipped text file. Sane defaults are included with this package.
            example_words_file (Optional(string)): Path to the file containing words from 
                which example passwords are built. Same format as other wordlists.
                Set this to `None` to not display examples.
            use_cached_example (Optional(bool)): If true, every help text will use the same
                example password, and passwords similar to it will be rejected. Defaults to
                `True` because Django's default caching behavior makes users copying the
                example password susceptible to attack by anyone loading the page at the
                same time. You are encouraged to disable caching on views where passwords are
                set and set this to `False`.
        """
        self.min_entropy = min_entropy

        wordlists = []
        for filename in os.listdir(wordlist_dir):
            path = os.path.join(wordlist_dir, filename)

            try:
                wordlist_lines = gzip.open(path).read().decode('utf-8').splitlines()
            except IOError:
                wordlist_lines = open(path).readlines()

            wordlists.append([word.strip() for word in wordlist_lines])

        self.tester = PatternStrengthTester(wordlists)

        self.example_words = None
        self.min_num_words = int(self.min_entropy / 10) + 1
        self.cached_example = None
        if example_words_file:
            try:
                example_words_lines = gzip.open(example_words_file).read().decode('utf-8').splitlines()
            except IOError:
                example_words_lines = open(example_words_file).readlines()

            self.example_words = [word.strip() for word in example_words_lines]
            self.min_num_words = int(self.min_entropy / log(len(self.example_words), 2)) + 1

            if use_cached_example:
                self.cached_example = self.generate_example()

    def generate_example(self):
        while True:
            example =  "".join(sample(self.example_words, self.min_num_words))

            try:
                self.validate(example)
                break
            except ValidationError:
                pass

        return example

    def validate(self, password, user=None):
        entropy = self.tester.strength(password)

        if entropy < self.min_entropy:
            raise ValidationError(
                _(("This password contains only {} bits of entropy, leaving it vulnerable to a "
                   "determined attacker. {}").format(entropy, self.get_help_text(True))),
                code='password_common_patterns',
            )

        if self.cached_example:
            example_similarity = SequenceMatcher(a=password.lower(), b=self.cached_example).ratio()

            if example_similarity > self.MAX_EXAMPLE_SIMILARITY:
                raise ValidationError(
                    _("Too similar to the default example. {}".format(self.get_help_text(True))),
                    code='password_common_patterns_matched_example',
                )

    def get_help_text(self, force_regenerate=False):
        if self.example_words:
            if force_regenerate or not self.cached_example:
                return _(("Your password must be complex (at least {} bits of entropy). "
                          "Try a phrase with at least {} different words. You could use "
                          "{}.").format(self.min_entropy, self.min_num_words, self.generate_example()))
            else:
                return _(("Your password must be complex (at least {} bits of entropy). "
                          "Try a phrase with at least {} different words. For example "
                          "{}.").format(self.min_entropy, self.min_num_words, self.cached_example))

        return _(("Passwords must be complex (at least {} bits of entropy). Try a phrase with "
                  "at least {} different words.").format(self.min_entropy, self.min_num_words))
