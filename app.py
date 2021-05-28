from flask import Flask,request,json
from flask_cors import CORS
from dictionary import attack_features
import numpy as np
from tensorflow.keras.models import load_model
app = Flask(__name__)


cors = CORS(app, resources={r"/*": {"origins": "*"}})

authKey = "123authKey123"

@app.route("/")
def home():
  return "I like food better than your face"

@app.route("/predict",methods=["POST"])
def predict():
  key = request.headers.get('authKey')
  if key != authKey:
    return {"msg":"Access Denied!!!"}


  res = request.get_json()['data']
  duration=res['duration']
  src_bytes=res['src_bytes']
  dst_bytes=res['dst_bytes']
  land=res['land']
  wrong_fragment=res['wrong_fragment']
  urgent=res['urgent']
  hot=res['hot']
  num_failed_logins=res['num_failed_logins']
  logged_in=res['logged_in']
  num_compromised=res['num_compromised']
  root_shell=res['root_shell']
  su_attempted=res['su_attempted']
  num_file_creations=res['num_file_creations']
  num_shells=res['num_shells']
  num_access_files=res['num_access_files']
  num_outbound_cmds=res['num_outbound_cmds']
  is_host_login=res['is_host_login']
  is_guest_login=res['is_guest_login']
  count=res['count']
  srv_count=res['srv_count']
  serror_rate=res['serror_rate']
  rerror_rate=res['rerror_rate']
  same_srv_rate=res['same_srv_rate']
  diff_srv_rate=res['diff_srv_rate']
  srv_diff_host_rate=res['srv_diff_host_rate']
  dst_host_count=res['dst_host_count']
  dst_host_srv_count=res['dst_host_srv_count']
  dst_host_diff_srv_rate = res['dst_host_diff_srv_rate']
  dst_host_same_src_port_rate = res['dst_host_same_src_port_rate']
  dst_host_srv_diff_host_rate = res['dst_host_srv_diff_host_rate']
  protocol_type = res['protocol_type']
  service = res['service']
  flag = res['flag']

  input_arr = attack_features(duration,src_bytes,dst_bytes,land,wrong_fragment,urgent,hot,num_failed_logins,logged_in,num_compromised,root_shell,su_attempted,num_file_creations,num_shells,num_access_files,num_outbound_cmds,is_host_login,is_guest_login,count,srv_count,serror_rate,rerror_rate,same_srv_rate,diff_srv_rate,srv_diff_host_rate,dst_host_count,dst_host_srv_count,dst_host_diff_srv_rate,dst_host_same_src_port_rate,dst_host_srv_diff_host_rate,protocol_type,service,flag)


  model = load_model('./model.h5')
  attack_type = model.predict([input_arr])
  attack_type = attack_type.flatten()
  index = np.argmax(attack_type)

  if(index == 0):
    return {"msg":"Valid Request Operation Succeded",
            "prefiction_probability":attack_type.tolist(),
            "attack_type":"normal"}

  elif(index == 1):
    return {"msg":"Valid Request Operation Succeded",
            "prefiction_probability":attack_type.tolist(),
            "attack_type":"u2r"}

  elif(index == 2):
    return {"msg":"Valid Request Operation Succeded",
            "prefiction_probability":attack_type.tolist(),
            "attack_type":"dos"}
  else:
    return {"msg":"Invalid Request"
            }
  

if __name__=='__main__':
  app.run(debug=True)