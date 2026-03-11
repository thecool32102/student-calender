import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

cursor.execute("INSERT INTO subjects (name, color) VALUES (?, ?)", ("Mathe", "blau"))
cursor.execute("INSERT INTO subjects (name, color) VALUES (?, ?)", ("Informatik", "grün"))

cursor.execute("""
    INSERT INTO tasks (title, description, due_date, priority, status, subject_id)
    VALUES (?, ?, ?, ?, ?, ?)
""", ("Hausaufgaben 1", "Kapitel 3 bearbeiten", "2026-03-15", "hoch", "offen", 1))

cursor.execute("""
    INSERT INTO tasks (title, description, due_date, priority, status, subject_id)
    VALUES (?, ?, ?, ?, ?, ?)
""", ("Python Übung", "Flask ausprobieren", "2026-03-16", "mittel", "in Bearbeitung", 2))

conn.commit()
conn.close()

print("Testdaten eingefügt.")