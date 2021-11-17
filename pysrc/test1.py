import os
import ember
import pickle
import argparse
import numpy as np


class ByteEntropyHistogram:
    ''' 2d byte/entropy histogram based loosely on (Saxe and Berlin, 2015).
    This roughly approximates the joint probability of byte value and local entropy.
    See Section 2.1.1 in https://arxiv.org/pdf/1508.03096.pdf for more info.
    '''

    name = 'byteentropy'
    dim = 256

    def __init__(self, step=1024, window=2048):
        self.window = window
        self.step = step

    def _entropy_bin_counts(self, block):
        # coarse histogram, 16 bytes per bin
        c = np.bincount(block >> 4, minlength=16)  # 16-bin histogram
        p = c.astype(np.float32) / self.window
        wh = np.where(c)[0]
        print("aaaaaa", p, wh)
        H = np.sum(-p[wh] * np.log2(
            p[wh])) * 2  # * x2 b.c. we reduced information by half: 256 bins (8 bits) to 16 bins (4 bits)
        print(H)
        Hbin = int(H * 2)  # up to 16 bins (max entropy is 8 bits)
        if Hbin == 16:  # handle entropy = 8.0 bits
            Hbin = 15

        return Hbin, c

    def raw_features(self, bytez, lief_binary):
        output = np.zeros((16, 16), dtype=np.int)
        a = np.frombuffer(bytez, dtype=np.uint8)
        if a.shape[0] < self.window:
            Hbin, c = self._entropy_bin_counts(a)
            output[Hbin, :] += c
        else:
            print(a.shape)
            # strided trick from here: http://www.rigtorp.se/2011/01/01/rolling-statistics-numpy.html
            shape = a.shape[:-1] + (a.shape[-1] - self.window + 1, self.window)
            print(shape, a.strides)
            strides = a.strides + (a.strides[-1],)
            print(strides)
            blocks1 = np.lib.stride_tricks.as_strided(a, shape=shape, strides=strides)
            print(len(blocks1))
            blocks = blocks1[::self.step, :]
            print(len(blocks))
            # from the blocks, compute histogram
            for block in blocks:
                Hbin, c = self._entropy_bin_counts(block)
                output[Hbin, :] += c

        return output.flatten().tolist()

    def process_raw_features(self, raw_obj):
        counts = np.array(raw_obj, dtype=np.float32)
        sum = counts.sum()
        normalized = counts / sum
        return normalized


prog = "classify_binaries"
descr = "Use a trained ember model to make predictions on PE files"
parser = argparse.ArgumentParser(prog=prog, description=descr)
parser.add_argument("binaries", metavar="BINARIES", type=str, nargs="+", help="PE files to classify")
args = parser.parse_args()

for binary_path in args.binaries:
    a = ember.PEFeatureExtractor()
    file_data = open(binary_path, "rb").read()
    print(a.raw_features(file_data))
    b = ByteEntropyHistogram().raw_features(file_data, None)
    print(b)
    