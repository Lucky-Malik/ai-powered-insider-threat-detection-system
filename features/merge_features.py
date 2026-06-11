import os
import pandas as pd
import networkx as nx

DATA_DIR = 'data'


def _compute_graph_features():
    file_access_path = os.path.join(DATA_DIR, 'file_access.csv')
    usb_usage_path = os.path.join(DATA_DIR, 'usb_usage.csv')
    if not os.path.exists(file_access_path) or not os.path.exists(usb_usage_path):
        return pd.DataFrame(columns=['user', 'degree_centrality', 'betweenness_centrality'])

    file_access = pd.read_csv(file_access_path, parse_dates=['access_time'])
    usb_usage = pd.read_csv(usb_usage_path, parse_dates=['plug_time', 'unplug_time'])
    G = nx.Graph()
    for _, row in file_access.iterrows():
        G.add_edge(row['user'], row['file'], type='access')
    for _, row in usb_usage.iterrows():
        G.add_edge(row['user'], row['device'], type='usb')

    users = sorted(set(file_access['user'].tolist() + usb_usage['user'].tolist()))
    degree = nx.degree_centrality(G)
    betweenness = nx.betweenness_centrality(G)
    return pd.DataFrame([
        {
            'user': user,
            'degree_centrality': float(degree.get(user, 0.0)),
            'betweenness_centrality': float(betweenness.get(user, 0.0)),
        }
        for user in users
    ])


def _compute_nlp_features():
    emails_path = os.path.join(DATA_DIR, 'emails.csv')
    if not os.path.exists(emails_path):
        return pd.DataFrame(columns=['sender', 'recipient', 'time', 'keyword_flag', 'subject_len', 'sentiment'])

    emails = pd.read_csv(emails_path, parse_dates=['time'], low_memory=False)
    if 'from' in emails.columns and 'sender' not in emails.columns:
        emails = emails.rename(columns={'from': 'sender'})
    if 'subject' not in emails.columns and 'content' in emails.columns:
        emails['subject'] = emails['content'].astype(str)
    if 'recipient' not in emails.columns:
        recipients = []
        for _, row in emails.iterrows():
            row_recipients = []
            for col in ['to', 'cc', 'bcc']:
                if col in row and pd.notna(row[col]):
                    row_recipients.extend([r.strip() for r in str(row[col]).replace('\n', ' ').split(';') if r.strip()])
            if not row_recipients:
                continue
            for recipient in row_recipients:
                recipients.append({
                    'sender': row['sender'],
                    'recipient': recipient,
                    'time': row['time'] if 'time' in row else None,
                    'subject': row.get('subject', ''),
                    'content': row.get('content', ''),
                })
        emails = pd.DataFrame(recipients)

    features = []
    for _, row in emails.iterrows():
        subject = str(row.get('subject', '') or '')
        keyword_flag = int(any(kw in subject.lower() for kw in ['confidential', 'urgent', 'password', 'secret', 'invoice', 'transfer']))
        subject_len = len(subject)
        features.append({
            'sender': row['sender'],
            'recipient': row.get('recipient', ''),
            'time': row.get('time'),
            'keyword_flag': keyword_flag,
            'subject_len': subject_len,
            'sentiment': 0,
        })
    return pd.DataFrame(features)


def merge_features():
    df_classic = pd.read_csv(os.path.join(DATA_DIR, 'features.csv'))

    graph_path = os.path.join(DATA_DIR, 'graph_features.csv')
    if os.path.exists(graph_path):
        df_graph = pd.read_csv(graph_path)
    else:
        df_graph = _compute_graph_features()

    nlp_path = os.path.join(DATA_DIR, 'nlp_email_features.csv')
    if os.path.exists(nlp_path):
        df_nlp = pd.read_csv(nlp_path, parse_dates=['time'], low_memory=False)
    else:
        df_nlp = _compute_nlp_features()

    red_team_path = os.path.join(DATA_DIR, 'red_team_users.csv')
    red_team = pd.read_csv(red_team_path)['user'].tolist() if os.path.exists(red_team_path) else []

    if 'sender' in df_nlp.columns and 'user' not in df_nlp.columns:
        df_nlp['user'] = df_nlp['sender'].str.replace('@company.com', '', regex=False)

    df_nlp_agg = df_nlp.groupby('user').agg({
        'keyword_flag': 'mean',
        'subject_len': 'mean',
        'sentiment': 'mean'
    }).reset_index()

    df = df_classic.merge(df_graph, on='user', how='left').merge(df_nlp_agg, on='user', how='left')
    df['is_red_team'] = df['user'].isin(red_team).astype(int)
    df.to_csv(os.path.join(DATA_DIR, 'merged_features.csv'), index=False)
    print('Merged features saved to data/merged_features.csv')


if __name__ == '__main__':
    merge_features()
