from flask import Flask, jsonify, request, abort
from dotenv import load_dotenv
import os
import psycopg2
import logging
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta

app = Flask(__name__)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=6)
jwt = JWTManager(app)

# Wczytanie zmiennych środowiskowych
load_dotenv()
logging.basicConfig(level=logging.INFO)

# Konfiguracja bazy danych
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT", 5432)
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")
API_KEY = os.getenv("API_KEY")  # Klucz API
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')

def get_db_connection():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        dbname=DB_NAME
    )

# API KEY Middleware (dotyczy tylko funkcji process_data)
def check_api_key():
    """
    Middleware do weryfikacji klucza API dla funkcji process_data.
    """
    api_key = request.headers.get("Authorization")
    if api_key != f"Bearer {API_KEY}":
        app.logger.warning("Nieprawidłowy klucz API.")
        abort(401, description="Unauthorized: Invalid API key")

# MOBILE APP SIDE

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"msg": "Username and password are required"}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Pobranie użytkownika z bazy danych
        cursor.execute("SELECT username, password FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if not user:
            app.logger.warning(f"Login failed for username: {username} (User not found)")
            return jsonify({"msg": "Invalid username or password"}), 401

        db_username, db_password = user

        # Porównanie hasła
        if password != db_password:
            app.logger.warning(f"Login failed for username: {username} (Incorrect password)")
            return jsonify({"msg": "Invalid username or password"}), 401

        # Generowanie tokenu JWT
        token = create_access_token(identity=db_username)

        # Jeśli token jest w formacie bytes, przekształć go na string
        if isinstance(token, bytes):
            token = token.decode('utf-8')

        app.logger.info(f"User {username} logged in successfully")

        # Zwrócenie tokenu w formacie JSON
        return jsonify({"access_token": token}), 200

    except Exception as e:
        app.logger.error(f"Error during login: {e}")
        return jsonify({"msg": "Internal server error"}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/mobile-get', methods=['GET'])
@jwt_required()  # Wymaga JWT
def get_user_data():
    # Pobranie ID użytkownika z tokenu JWT
    user_id = get_jwt_identity()
    try:
        # Połączenie z bazą danych
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id
            FROM users
            WHERE username = %s
        """, (user_id,))

        id = cursor.fetchone()

        if not id:
            return jsonify({"msg": f"No active user {user_id}"}), 404

        cursor.execute("""
            SELECT serial_master
            FROM masters
            WHERE id_user = %s
        """, (id,))

        masters = cursor.fetchall()

        if not masters:
            return jsonify({"msg": f"No masters attached to {user_id}"}), 404

        devices_data = []
        for master in masters:
            master_data = {
                "serial_master": master[0],  # serial_master to pierwszy element z tuple
                "serial_slaves": []
            }

            # Zapytanie SQL, które sprawdza, które serial_slave_x istnieją w tabeli masters
            cursor.execute("""
                SELECT serial_slave_1, serial_slave_2, serial_slave_3, serial_slave_4, serial_slave_5, 
                       serial_slave_6, serial_slave_7, serial_slave_8, serial_slave_9, serial_slave_10  
                FROM masters
                WHERE serial_master = %s
            """, (master[0],))

            # Pobranie wyników
            slave_list = cursor.fetchone()

            # Lista istniejących serial_slave_x w odpowiedniej kolejności
            existing_slaves = [
                (f"serial_slave_{i}", slave_list[i - 1])  # przypisujemy numer i wartość serial_slave
                for i in range(1, 11) if slave_list[i - 1] is not None
            ]

            # Jeśli istnieją jakiekolwiek serial_slave_x, wykonaj zapytanie po dane pomiarowe
            for slave_name, slave_serial in existing_slaves:
                # Pobranie danych pomiarowych dla serial_slave
                cursor.execute("""
                    SELECT timestamp, lux, temperature, humidity, pressure
                    FROM sensor_data
                    WHERE serial_slave = %s
                    ORDER BY timestamp DESC LIMIT 1  -- Pobieramy tylko ostatni pakiet danych
                """, (slave_serial,))

                data = cursor.fetchone()

                # Pobieranie wartości light_mode i light_value z tabeli control_data
                cursor.execute("""
                    SELECT light_mode, light_value
                    FROM control_data
                    WHERE serial_slave = %s
                """, (slave_serial,))

                control_data = cursor.fetchone()

                # Jeśli dane istnieją, dodajemy je do listy serial_slaves
                slave_data = {
                    "data": {
                        "timestamp": data[0].strftime("%a, %d %b %Y %H:%M:%S GMT") if data else None,
                        "lux": data[1] if data else None,
                        "temperature": data[2] if data else None,
                        "humidity": data[3] if data else None,
                        "pressure": data[4] if data else None,
                        "light_mode": control_data[0] if control_data else None,
                        "light_value": control_data[1] if control_data else None
                    }
                }

                # Dodajemy do odpowiedniej pozycji serial_slave
                slave_data[slave_name] = slave_serial
                master_data["serial_slaves"].append(slave_data)

            # Dodajemy dane dla serial_master do devices_data
            devices_data.append(master_data)

        # Zwracamy dane
        return jsonify(devices_data), 200

    except Exception as e:
        app.logger.error(f"Error retrieving user data: {e}")
        return jsonify({"msg": "Internal server error"}), 500

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route('/mobile-put', methods=['POST'])
@jwt_required()  # Wymaga JWT
def put_user_data():
    # Pobranie ID użytkownika z tokenu JWT
    user_id = get_jwt_identity()

    # Odbiór danych z żądania JSON
    # data = request.get_json()
    data = json.loads(data)

    # Weryfikacja, czy dane są poprawnie sformatowane
    if not isinstance(data, dict):
        return jsonify({"msg": "Invalid data format, expected an object"}), 400

    # Weryfikacja obecności serial_master
    serial_master = data.get("serial_master")
    if not serial_master:
        return jsonify({"msg": "serial_master is required"}), 400

    # Weryfikacja, czy serial_master jest ciągiem znaków
    if not isinstance(serial_master, str):
        return jsonify({"msg": "serial_master should be a string"}), 400

    # Pobranie serial_slaves
    serial_slaves = data.get("serial_slaves", [])
    if not isinstance(serial_slaves, list):
        return jsonify({"msg": "serial_slaves should be a list"}), 400

    try:
        # Połączenie z bazą danych
        conn = get_db_connection()
        cursor = conn.cursor()

        # Sprawdzenie, czy serial_master istnieje
        cursor.execute("SELECT 1 FROM masters WHERE serial_master = %s", (serial_master,))
        if not cursor.fetchone():
            return jsonify({"msg": f"Serial master {serial_master} not found"}), 404

        # Iteracja po serial_slaves
        for slave in serial_slaves:
            # Sprawdzenie klucza i wartości dla każdego slave
            for slave_key, slave_serial in slave.items():
                if slave_key.startswith("serial_slave"):
                    # Weryfikacja, czy serial_slave jest ciągiem znaków
                    if not isinstance(slave_serial, str):
                        return jsonify({"msg": f"serial_slave should be a string for {slave_key}"}), 400

                    control_data = slave.get("control_data", {})
                    light_mode = control_data.get("light_mode")
                    light_value = control_data.get("light_value")

                    # Weryfikacja danych control_data
                    if light_mode is None or light_value is None:
                        return jsonify({"msg": f"Missing control data for {slave_serial}"}), 400

                    if not isinstance(light_mode, bool):
                        return jsonify({"msg": f"Invalid light_mode for {slave_serial}, expected bool"}), 400

                    # Sprawdzenie, czy serial_slave istnieje w tabeli masters
                    cursor.execute("""
                        SELECT 1 FROM masters 
                        WHERE %s IN (
                            serial_slave_1, serial_slave_2, serial_slave_3, serial_slave_4, serial_slave_5,
                            serial_slave_6, serial_slave_7, serial_slave_8, serial_slave_9, serial_slave_10
                        )
                    """, (slave_serial,))
                    if not cursor.fetchone():
                        return jsonify({"msg": f"Serial slave {slave_serial} not found in masters"}), 404

                    # Wstawianie lub aktualizowanie danych w tabeli control_data
                    cursor.execute("""
                        INSERT INTO control_data (serial_slave, light_mode, light_value)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (serial_slave) 
                        DO UPDATE SET light_mode = EXCLUDED.light_mode, light_value = EXCLUDED.light_value
                    """, (slave_serial, light_mode, light_value))

        # Zatwierdzenie transakcji
        conn.commit()

        return jsonify({"msg": "Control data inserted/updated successfully"}), 200

    except Exception as e:
        app.logger.error(f"Error inserting control data: {e}")
        return jsonify({"msg": "Internal server error"}), 500

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


# MICROCONTROLLER SIDE

@app.route('/data', methods=['POST'])
def process_data():
    """
    Endpoint do przetwarzania danych JSON:
    1. Weryfikuje klucz API.
    2. Wykonuje logikę przetwarzania danych.
    """
    # Weryfikacja klucza API
    check_api_key()

    data = request.get_json()

    # Wymagane pola
    required_fields = ['serial_master', 'timestamp']
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields: serial_master, timestamp"}), 400

    serial_master = data['serial_master']
    timestamp = data['timestamp']

    # Domyślnie traktujemy brak serial_slave* jako null
    serial_slaves = {
        f"serial_slave_{i}": data.get(f"serial_slave_{i}", None)
        for i in range(1, 11)
    }

    data_slaves = {
        f"data_slave_{i}": data.get(f"data_slave_{i}", None)
        for i in range(1, 11)
    }

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # 1. Sprawdzenie, czy serial_master istnieje w tabeli masters
        cursor.execute("SELECT id FROM masters WHERE serial_master = %s", (serial_master,))
        master_exists = cursor.fetchone()

        if not master_exists:
            app.logger.info(f"Device with serial_master {serial_master} connected but not found in the database.")
            return jsonify({"error": f"serial_master {serial_master} does not exist in the database"}), 404

        app.logger.info(f"Device with serial_master {serial_master} connected successfully.")

        # 2. Sprawdzenie i aktualizacja serial_slave* w tabeli masters
        update_query = """
            UPDATE masters
            SET serial_slave_1 = %s, serial_slave_2 = %s, serial_slave_3 = %s, serial_slave_4 = %s,
                serial_slave_5 = %s, serial_slave_6 = %s, serial_slave_7 = %s, serial_slave_8 = %s,
                serial_slave_9 = %s, serial_slave_10 = %s
            WHERE serial_master = %s
        """
        cursor.execute(update_query, (
            serial_slaves['serial_slave_1'], serial_slaves['serial_slave_2'], serial_slaves['serial_slave_3'],
            serial_slaves['serial_slave_4'], serial_slaves['serial_slave_5'], serial_slaves['serial_slave_6'],
            serial_slaves['serial_slave_7'], serial_slaves['serial_slave_8'], serial_slaves['serial_slave_9'],
            serial_slaves['serial_slave_10'],
            serial_master
        ))

        # 3. Wprowadzanie danych do sensor_data
        for i in range(1, 11):
            serial_slave_key = f"serial_slave_{i}"
            data_slave_key = f"data_slave_{i}"

            # Pobieramy serial_slave i data_slave z JSON, jeśli istnieją
            serial_slave = serial_slaves.get(serial_slave_key)  # Zwróci None, jeśli nie ma takiego klucza
            data_slave = data_slaves.get(data_slave_key)  # Zwróci None, jeśli nie ma takiego klucza

            # Sprawdzamy, czy serial_slave i data_slave istnieją
            if serial_slave and data_slave:
                cursor.execute("""
                    INSERT INTO sensor_data (serial_slave, timestamp, lux, temperature, humidity, pressure)
                    VALUES (%s, TO_TIMESTAMP(%s), %s, %s, %s, %s)
                    ON CONFLICT (serial_slave) 
                    DO UPDATE SET
                        timestamp = EXCLUDED.timestamp,
                        lux = EXCLUDED.lux,
                        temperature = EXCLUDED.temperature,
                        humidity = EXCLUDED.humidity,
                        pressure = EXCLUDED.pressure
                """, (
                    serial_slave, timestamp,
                    data_slave.get('lux', None),  # Jeśli brak danych, używamy None
                    data_slave.get('temperature', None),  # Jeśli brak danych, używamy None
                    data_slave.get('humidity', None),  # Jeśli brak danych, używamy None
                    data_slave.get('pressure', None)  # Jeśli brak danych, używamy None
                ))
                # Logowanie zmiany w sensor_data
                app.logger.info(f"Data inserted/updated for serial_slave_{i} (serial_slave: {serial_slave})")

        # 4. Pobieranie danych z control_data
        response_data = {}
        for i in range(1, 11):
            serial_slave_key = f"serial_slave_{i}"
            serial_slave = serial_slaves[serial_slave_key]

            if serial_slave:
                cursor.execute("""
                    SELECT light_mode, light_value
                    FROM control_data
                    WHERE serial_slave = %s
                """, (serial_slave,))
                result = cursor.fetchone()
                if result:
                    response_data[serial_slave] = {
                        "light_mode": result[0],
                        "light_value": result[1]
                    }
                else:
                    response_data[serial_slave] = {"light_mode": None, "light_value": None}

        conn.commit()
    except Exception as e:
        app.logger.error("Error processing data: %s", e)
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    return jsonify(response_data), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
