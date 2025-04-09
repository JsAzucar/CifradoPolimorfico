import random
import time

# ------------------------
# PASO 1: FUNCIONES DE LLAVES
# ------------------------

def fs(P, S):
    return (P ^ S) + ((P & S) << 1)

def fg(P0, Q):
    return (P0 * Q) ^ (P0 >> 3)

def fm(S, Q):
    return (S + Q) ^ (S << 2)

def generar_tabla_llaves(P, Q, S, num_llaves=5):
    llaves = []
    for _ in range(num_llaves):
        P0 = fs(P, S)
        llave = fg(P0, Q) & ((1 << 64) - 1)
        llaves.append(llave)
        S = fm(S, Q)
    return llaves

def generar_primo_pequeno():
    primos = [17, 19, 23, 29, 31, 37, 41, 43, 47, 53]
    return random.choice(primos)

# ------------------------
# PASO 2: FUNCIONES DE CIFRADO/REVERSIBLES
# ------------------------

def xor_con_llave(valor, llave):
    return valor ^ llave

def rotar_izquierda(valor, bits=3, total_bits=64):
    return ((valor << bits) | (valor >> (total_bits - bits))) & ((1 << total_bits) - 1)

def rotar_derecha(valor, bits=3, total_bits=64):
    return ((valor >> bits) | (valor << (total_bits - bits))) & ((1 << total_bits) - 1)

# ------------------------
# PASO 3: CIFRADO Y DESCIFRADO CON PSN
# ------------------------

def cifrar_con_psn(payload, llave, psn):
    for i in range(4):
        bit = (psn >> (3 - i)) & 1
        if bit:
            if i == 0:
                payload = xor_con_llave(payload, llave)
            elif i == 1:
                payload = rotar_derecha(payload, bits=3)
            elif i == 2:
                payload = rotar_izquierda(payload, bits=3)
            elif i == 3:
                payload = xor_con_llave(payload, llave)
    return payload

def descifrar_con_psn(payload, llave, psn):
    for i in range(3, -1, -1):
        bit = (psn >> (3 - i)) & 1
        if bit:
            if i == 3:
                payload = xor_con_llave(payload, llave)
            elif i == 2:
                payload = rotar_derecha(payload, bits=3)
            elif i == 1:
                payload = rotar_izquierda(payload, bits=3)
            elif i == 0:
                payload = xor_con_llave(payload, llave)
    return payload

# ------------------------
# PASO 4: CONVERSIÓN TEXTO <-> NÚMERO
# ------------------------

def texto_a_numero(texto):
    return int.from_bytes(texto.encode('utf-8'), byteorder='big')

def numero_a_texto(numero):
    longitud = (numero.bit_length() + 7) // 8
    return numero.to_bytes(longitud, byteorder='big').decode('utf-8')

# ------------------------
# SIMULACIÓN COMPLETA
# ------------------------

# 1. Generar primos y semilla
P = generar_primo_pequeno()
Q = generar_primo_pequeno()
while Q == P:
    Q = generar_primo_pequeno()
S = int(time.time()) % 1000

# 2. Generar tabla de llaves
tabla_llaves = generar_tabla_llaves(P, Q, S)

# Mostrar todas las llaves generadas
print("\n Llaves generadas (64 bits):")
for i, k in enumerate(tabla_llaves, 1):
    print(f"  Llave {i}: {k} -> bin: {format(k, '064b')}")

llave = tabla_llaves[0]

# 3. Crear mensaje con TEXTO
mensaje = {
    "id": 1,
    "tipo": "FCM",
    "psn": 0b1011,
    "payload":"Jose"  # texto a cifrar
}

# 4. Convertir texto a número y cifrar
payload_num = texto_a_numero(mensaje["payload"])
payload_cifrado = cifrar_con_psn(payload_num, llave, mensaje["psn"])

# 5. Descifrar y convertir número a texto
payload_descifrado_num = descifrar_con_psn(payload_cifrado, llave, mensaje["psn"])
payload_descifrado_texto = numero_a_texto(payload_descifrado_num)

# ------------------------
# RESULTADOS
# ------------------------

print(f"\nP = {P}, Q = {Q}, S = {S}")
print(f"Llave usada: {llave}")
print(f"Mensaje original:        {mensaje['payload']}")
print(f"PSN:                     {bin(mensaje['psn'])}")
print(f"Payload cifrado (num):   {payload_cifrado}")
print(f"Payload descifrado:      {payload_descifrado_texto}")
