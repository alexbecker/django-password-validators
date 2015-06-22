from django.core.exceptions import ValidationError
from django.utils.translation import ugettext as _
from django.utils._os import upath
from django.template.loader import render_to_string

from math import log
from random import sample

from .password_strength import PatternStrengthTester

import os
import gzip

class CommonPatternValidator(object):
    """
    Estimates the entropy of a password against a sophisticated attack which exploits
    common password patterns in combination with various wordlists.
    If the password entropy is below the set threshold, a ValidationError is raised.
    Sane defaults for the wordlists are provided consisting of common names, nouns and words.
    """
    DEFAULT_WORDLIST_DIR = os.path.join(
        os.path.dirname(os.path.realpath(upath(__file__))), 'wordlists'
    )

    DEFAULT_EXAMPLE_WORDS_FILE = os.path.join(
        os.path.dirname(os.path.realpath(upath(__file__))), 'example_words.txt'
    )

    def __init__(self, min_entropy=25, wordlist_dir=DEFAULT_WORDLIST_DIR, 
            example_words_file=DEFAULT_EXAMPLE_WORDS_FILE, generate_examples=False):
        self.min_entropy = min_entropy
        self.generate_examples = generate_examples

        wordlists = []
        for filename in os.listdir(wordlist_dir):
            path = os.path.join(wordlist_dir, filename)

            try:
                wordlist_lines = gzip.open(path).read().decode('utf-8').splitlines()
            except IOError:
                wordlist_lines = open(path).readlines()

            wordlists.append([word.strip() for word in wordlist_lines])

        self.tester = PatternStrengthTester(wordlists)

        if generate_examples:
            try:
                example_words_lines = gzip.open(example_words_file).read().decode('utf-8').splitlines()
            except IOError:
                example_words_lines = open(example_words_file).readlines()

            self.example_words = [word.strip() for word in example_words_lines]
        else:
            self.example_words = None

    def validate(self, password, user=None):
        entropy = self.tester.strength(password)

        if entropy < self.min_entropy:
            raise ValidationError(
                _(("This password contains only {} bits of entropy, leaving it vulnerable to a "
                   "determined attacker. {}").format(entropy, self.get_help_text())),
                code='password_common_patterns',
            )

    def get_help_text(self):
        if not self.generate_examples:
            min_num_words = int(self.min_entropy / 10) + 1

            return _(("Passwords must contain at least {} bits of entropy. Try a phrase with "
                      "at least {} different words.").format(self.min_entropy, min_num_words))

        min_num_words = int(self.min_entropy / log(len(self.example_words), 2)) + 1

        if self.generate_examples == 'server':
            example = "".join(sample(self.example_words, min_num_words))

            return _(("Your password must have at least {} bits of entropy. "
                      "Try a phrase with at least {} different words, such as "
                      "{}.").format(self.min_entropy, min_num_words, example))

        return _(render_to_string('password_validators/help_text.html', {
            'min_entropy': self.min_entropy, 
            'min_num_words': min_num_words,
            'example_words': self.example_words,
        }))
