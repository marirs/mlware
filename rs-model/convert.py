import os
import ember
import pickle

model = open('model.pickle', 'rb')
lgbm_model = pickle.load(model)
lgbm_model.save_model("model.txt")
