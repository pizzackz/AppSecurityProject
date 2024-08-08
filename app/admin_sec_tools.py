from faker import Faker
from models import Log_account

fake = Faker()

def create_fake_logs(num_logs):
    for _ in range(num_logs):
        log = Log_account(
            log_datetime=fake.date_time_this_year(),
            priority_level=fake.random_element(elements=('Info', 'Error', 'Critical')),
            user_id=fake.random_int(min=1, max=1000),
            file_subdir=fake.file_path(depth=3),
            log_info=fake.sentence(nb_words=10)
        )
        db.session.add(log)
    db.session.commit()

if __name__ == '__main__':
    create_fake_logs(20)
    print("Added 20 fake log entries to the database.")