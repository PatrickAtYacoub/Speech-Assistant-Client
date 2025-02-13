import speech_recognition as sr
from pydub import AudioSegment
from pydub.playback import play
from apicall import api
import noisereduce as nr
import numpy as np
from signed_call import generate_url
import requests
from gtts import gTTS
import os

def clean_audio(audio):
    audio_data = np.frombuffer(audio.get_raw_data(), dtype=np.int16)
    reduced_noise = nr.reduce_noise(y=audio_data, sr=audio.sample_rate)
    return sr.AudioData(reduced_noise.tobytes(), audio.sample_rate, audio.sample_width)

def save_audio_to_file(audio, filename="temp_audio.wav"):
    with open(filename, "wb") as f:
        f.write(audio.get_wav_data())

def get_transcription(filename, language="de"):
    response = api.send_request("whisper", filename, language=language)
    return response.get("args", {}).get("output", "")

def process_command(command):
    url = generate_url('http://10.100.100.12:5001/', 'app.llm.db_agents', 'alice', prompt=command)
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Request failed with status code {response.status_code}")
        return None

def listen_for_wake_word():
    recognizer = sr.Recognizer()
    recognizer.energy_threshold = 8000
    recognizer.dynamic_energy_threshold = True
    with sr.Microphone() as source:
        print("Warte auf 'Hey Murphy'...")
        while True:
            try:
                audio = recognizer.listen(source)
                if len(audio.frame_data) < 4 * audio.sample_rate:
                    print("Audio zu kurz, Programm wird beendet.")
                    continue
                save_audio_to_file(audio)
                text = get_transcription("temp_audio.wav")
                if not text or text == ".":
                    continue
                print("Erkannt:", text)
                text = text.lower()
                if "hey murphy" in text or "hey murrphy" in text:
                    command = text.replace("hey murphy", "").replace("hey murrphy", "").strip()
                    print("Befehl:", command)
                    response = process_command(command)
                    if response:
                        print(response)
                    print("Antwort:", response)
                    if response:
                        tts = gTTS(text=response, lang='en')
                        tts.save("response.mp3")
                        sound = AudioSegment.from_mp3("response.mp3")
                        play(sound)
            except sr.UnknownValueError:
                pass
            except sr.RequestError:
                print("Fehler bei der Spracherkennung")

if __name__ == "__main__":
    listen_for_wake_word()
