import ember
import pickle
ember.create_vectorized_features("./ember_malware/ember2018/")
lgbm_model = ember.train_model("./ember_malware/ember2018/")

try:
    with open('./ember_malware/model.pickle', 'wb') as handle:
        pickle.dump(lgbm_model, handle, protocol=pickle.HIGHEST_PROTOCOL)
except:
    print('Error Saving Model')
    pass
