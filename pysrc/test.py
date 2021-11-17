import os
import ember
import pickle

model = open('model.pickle', 'rb')
lgbm_model = pickle.load(model)

lgbm_model.save_model("model.txt")


with open('./ember_malware/results.txt', 'w') as f:
    for (root,dir,files) in os.walk('./ember_malware/all_files', topdown=True):
        for file in files:
            print(file)
            try:
                putty_data = open('./ember_malware/all_files/'+file, 'rb').read()
                print(ember.predict_sample(lgbm_model, putty_data))
                if ember.predict_sample(lgbm_model, putty_data) < 0.1:
                    label = "Goodware"
                else:
                    label = "Malware"
                f.write(f'{file} is labeled {label} with Confidence: {ember.predict_sample(lgbm_model, putty_data)}\n\n')
            except:
                f.write(f'{file} Detection Failed, Could Potentially be Malware\n\n')
                print('failed'
                      '')

