import os
import re
from pathlib import Path
from datetime import datetime, timedelta
import pandas as pd
import networkx as nx

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / 'data'
R42_DIR = ROOT / 'r4.2'
ANSWERS_DIR = ROOT / 'answers'

DATE_FORMAT = '%m/%d/%Y %H:%M:%S'


def parse_datetime(value):
    if pd.isna(value):
        return None
    value = str(value).strip()
    return datetime.strptime(value, DATE_FORMAT)


def ensure_data_dir():
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def normalize_recipients(value):
    if pd.isna(value):
        return []
    if isinstance(value, str):
        value = value.replace('\n', ' ')
        parts = re.split(r'[;,	]+', value)
        return [p.strip() for p in parts if p.strip()]
    return []


def pair_sessions(df, start_event, end_event, event_col='activity', time_col='date', default_duration=timedelta(hours=1)):
    sessions = []
    if df.empty:
        return pd.DataFrame(columns=['user', 'pc', 'start', 'end'])

    df = df.copy()
    df['parsed_date'] = df[time_col].apply(parse_datetime)
    df = df.sort_values('parsed_date')
    active = {}

    for _, row in df.iterrows():
        key = (row['user'], row['pc'])
        activity = str(row[event_col]).strip().lower()
        if activity == start_event.lower():
            active.setdefault(key, []).append(row['parsed_date'])
        elif activity == end_event.lower():
            if active.get(key):
                start_time = active[key].pop(0)
                sessions.append({'user': row['user'], 'pc': row['pc'], 'start': start_time, 'end': row['parsed_date']})
            else:
                # If we see an end event without a matching start, ignore it.
                continue

    for key, starts in active.items():
        for start_time in starts:
            sessions.append({'user': key[0], 'pc': key[1], 'start': start_time, 'end': start_time + default_duration})

    return pd.DataFrame(sessions)


def convert_logon_sessions():
    print('Converting r4.2 logon data to data/logins.csv...')
    df = pd.read_csv(R42_DIR / 'logon.csv', dtype=str)
    sessions = pair_sessions(df, 'Logon', 'Logoff', event_col='activity', time_col='date')
    sessions = sessions.rename(columns={'start': 'login', 'end': 'logout'})
    sessions.to_csv(DATA_DIR / 'logins.csv', index=False)
    print(f'Wrote {len(sessions)} login sessions.')


def convert_device_sessions():
    print('Converting r4.2 device data to data/usb_usage.csv...')
    df = pd.read_csv(R42_DIR / 'device.csv', dtype=str)
    sessions = pair_sessions(df, 'Connect', 'Disconnect', event_col='activity', time_col='date')
    sessions = sessions.rename(columns={'start': 'plug_time', 'end': 'unplug_time'})
    sessions['device'] = sessions['pc']
    sessions = sessions[['user', 'device', 'plug_time', 'unplug_time']]
    sessions.to_csv(DATA_DIR / 'usb_usage.csv', index=False)
    print(f'Wrote {len(sessions)} USB sessions.')


def convert_file_access():
    print('Converting r4.2 file data to data/file_access.csv...')
    df = pd.read_csv(R42_DIR / 'file.csv', dtype=str)
    df['access_time'] = df['date'].apply(parse_datetime)
    output = df[['user', 'filename', 'access_time']].rename(columns={'filename': 'file'})
    output.to_csv(DATA_DIR / 'file_access.csv', index=False)
    print(f'Wrote {len(output)} file access rows.')


def convert_emails():
    print('Converting r4.2 email data to data/emails.csv...')
    df = pd.read_csv(R42_DIR / 'email.csv', dtype=str)
    if 'date' not in df.columns:
        raise RuntimeError('r4.2 email.csv does not contain expected date column')

    rows = []
    for _, row in df.iterrows():
        timestamp = parse_datetime(row['date'])
        sender = row.get('from') or row.get('sender') or ''
        sender = str(sender).strip()
        recipients = normalize_recipients(row.get('to', ''))
        recipients += normalize_recipients(row.get('cc', ''))
        recipients += normalize_recipients(row.get('bcc', ''))
        if not recipients:
            continue

        subject = str(row.get('content', '')).strip()
        for recipient in recipients:
            rows.append({
                'sender': sender,
                'recipient': recipient,
                'time': timestamp,
                'subject': subject,
                'content': row.get('content', ''),
            })

    emails = pd.DataFrame(rows)
    emails.to_csv(DATA_DIR / 'emails.csv', index=False)
    print(f'Wrote {len(emails)} email rows.')


def create_red_team_users():
    print('Creating red team label file from answers/insiders.csv...')
    path = ANSWERS_DIR / 'insiders.csv'
    if not path.exists():
        print('answers/insiders.csv not found; skipping red team label creation.')
        return

    answers = pd.read_csv(path, dtype=str)
    answers['dataset'] = answers['dataset'].astype(str)
    red_users = answers[answers['dataset'].str.startswith('4.2')]['user'].dropna().unique()
    if len(red_users) == 0:
        print('No red team users found for dataset 4.2 in answers/insiders.csv.')
        return

    pd.DataFrame({'user': sorted(red_users)}).to_csv(DATA_DIR / 'red_team_users.csv', index=False)
    print(f'Wrote {len(red_users)} red team users.')


def create_graph_features():
    print('Creating graph features from converted file_access and usb_usage...')
    file_access_path = DATA_DIR / 'file_access.csv'
    usb_usage_path = DATA_DIR / 'usb_usage.csv'
    if not file_access_path.exists() or not usb_usage_path.exists():
        print('Missing file_access.csv or usb_usage.csv; skipping graph feature creation.')
        return

    file_access = pd.read_csv(file_access_path, parse_dates=['access_time'])
    usb_usage = pd.read_csv(usb_usage_path, parse_dates=['plug_time', 'unplug_time'])
    G = nx.Graph()
    for _, row in file_access.iterrows():
        G.add_edge(row['user'], row['file'], type='access')
    for _, row in usb_usage.iterrows():
        G.add_edge(row['user'], row['device'], type='usb')

    user_nodes = sorted({u for u in file_access['user'].unique().tolist() + usb_usage['user'].unique().tolist()})
    degree = nx.degree_centrality(G)
    betweenness = nx.betweenness_centrality(G)
    records = []
    for user in user_nodes:
        records.append({
            'user': user,
            'degree_centrality': float(degree.get(user, 0.0)),
            'betweenness_centrality': float(betweenness.get(user, 0.0)),
        })

    pd.DataFrame(records).to_csv(DATA_DIR / 'graph_features.csv', index=False)
    print(f'Wrote graph features for {len(records)} users.')


def main():
    ensure_data_dir()
    convert_logon_sessions()
    convert_device_sessions()
    convert_file_access()
    convert_emails()
    create_red_team_users()
    create_graph_features()

    try:
        from features.feature_engineering import extract_features as extract_classic
        from features.nlp_email_features import extract_features as extract_nlp
        from features.merge_features import merge_features
    except Exception as exc:
        raise RuntimeError('Unable to import feature pipeline modules. Run from repository root.') from exc

    extract_classic()
    extract_nlp()
    merge_features()
    print('r4.2 dataset converted and merged features created. Run models/train.py next.')


if __name__ == '__main__':
    main()
