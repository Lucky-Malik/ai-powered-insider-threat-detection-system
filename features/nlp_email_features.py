import pandas as pd
import os

DATA_DIR = 'data'
SUSPICIOUS_KEYWORDS = ['confidential', 'urgent', 'password', 'secret', 'invoice', 'transfer']


def _normalize_recipients(value):
    if pd.isna(value):
        return []
    return [recipient.strip() for recipient in str(value).replace('\n', ' ').split(';') if recipient.strip()]

def extract_features():
    emails = pd.read_csv(os.path.join(DATA_DIR, 'emails.csv'), parse_dates=['time'], low_memory=False)
    if 'from' in emails.columns and 'sender' not in emails.columns:
        emails = emails.rename(columns={'from': 'sender'})
    if 'date' in emails.columns and 'time' not in emails.columns:
        emails = emails.rename(columns={'date': 'time'})
    if 'subject' not in emails.columns and 'content' in emails.columns:
        emails['subject'] = emails['content'].astype(str)

    if 'recipient' not in emails.columns:
        expanded_rows = []
        for _, row in emails.iterrows():
            recipients = []
            for col in ['to', 'cc', 'bcc']:
                if col in row and pd.notna(row[col]):
                    recipients.extend(_normalize_recipients(row[col]))
            if not recipients:
                continue
            for recipient in recipients:
                expanded_rows.append({
                    'sender': row['sender'],
                    'recipient': recipient,
                    'time': row['time'],
                    'subject': row.get('subject', ''),
                })
        emails = pd.DataFrame(expanded_rows)

    features = []
    for _, row in emails.iterrows():
        subject = str(row.get('subject', '') or '')
        keyword_flag = int(any(kw in subject.lower() for kw in SUSPICIOUS_KEYWORDS))
        subject_len = len(subject)
        sentiment = 0
        features.append({
            'sender': row['sender'],
            'recipient': row.get('recipient', ''),
            'time': row.get('time'),
            'keyword_flag': keyword_flag,
            'subject_len': subject_len,
            'sentiment': sentiment
        })
    pd.DataFrame(features).to_csv(os.path.join(DATA_DIR, 'nlp_email_features.csv'), index=False)
    print('NLP email features saved to data/nlp_email_features.csv')

if __name__ == '__main__':
    extract_features() 