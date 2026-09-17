"""
CyberTrace AI Preprocessing Module
----------------------------------
This file uses Pandas to clean and prepare security logs for forensic analysis.

Beginner Concepts:
- What is Pandas?
  Pandas is a powerful Python library used for working with structured data (like tables/spreadsheets).
- What is a DataFrame?
  A DataFrame is like a 2D Excel sheet or SQL table stored in Python memory with rows and columns.
- Why are we cleaning the data?
  Security logs often have missing values, inconsistent spaces, or wrong data types.
  Cleaning ensures our anomaly detection math and database queries never crash.
"""

import pandas as pd
import io
from typing import Union, List, Dict, Any, Tuple


# Expected columns in standard cybersecurity logs
REQUIRED_COLUMNS = [
    'timestamp',
    'user',
    'device',
    'ip',
    'event_type',
    'action',
    'file',
    'data_size'
]


def load_and_clean_csv(data_source: Union[str, bytes, io.StringIO]) -> Tuple[pd.DataFrame, List[Dict[str, Any]], str]:
    """
    Reads a CSV file or text content, checks for errors, cleans values,
    and returns a clean Pandas DataFrame and a Python list of dictionaries.
    
    Returns:
        (df, records_list, error_message)
    """
    try:
        # Step 1: Read the CSV data using Pandas
        if isinstance(data_source, bytes):
            # Decode bytes to text
            text_data = data_source.decode('utf-8', errors='ignore')
            df = pd.read_csv(io.StringIO(text_data))
        elif isinstance(data_source, str) and (',' in data_source or '\n' in data_source) and not data_source.endswith('.csv'):
            # It's a raw CSV string
            df = pd.read_csv(io.StringIO(data_source))
        else:
            # It's a file path
            df = pd.read_csv(data_source)
        
        # Check if CSV is completely empty
        if df.empty:
            return pd.DataFrame(), [], "The uploaded CSV file is empty."
        
        # Step 2: Normalize column headers (strip whitespace and convert to lowercase)
        df.columns = [str(c).strip().lower() for c in df.columns]
        
        # Check for missing required columns
        missing_cols = [col for col in REQUIRED_COLUMNS if col not in df.columns]
        if missing_cols:
            return pd.DataFrame(), [], f"Missing required columns in CSV: {', '.join(missing_cols)}"
        
        # Step 3: Handle missing values (NaN) safely
        # Text fields get empty string, numeric fields get 0
        df['file'] = df['file'].fillna('').astype(str).str.strip()
        df['data_size'] = pd.to_numeric(df['data_size'], errors='coerce').fillna(0).astype(int)
        
        # Clean string columns: remove accidental extra spaces
        string_columns = ['timestamp', 'user', 'device', 'ip', 'event_type', 'action']
        for col in string_columns:
            df[col] = df[col].fillna('UNKNOWN').astype(str).str.strip()
            # Standardize event_type and action to UPPERCASE for consistency
            if col in ['event_type', 'action']:
                df[col] = df[col].str.upper()

        # Step 4: Remove exact duplicate rows (accidental repeat log entries)
        initial_count = len(df)
        df = df.drop_duplicates().reset_index(drop=True)
        
        # Step 5: Convert DataFrame rows into simple Python dictionaries
        records = df.to_dict(orient='records')
        
        return df, records, ""
        
    except Exception as e:
        # Return a friendly error message if parsing fails
        return pd.DataFrame(), [], f"Failed to read CSV file: {str(e)}"


def get_dataset_summary(df: pd.DataFrame) -> Dict[str, Any]:
    """
    Computes quick statistics about the cleaned dataset for the dashboard.
    """
    if df.empty:
        return {
            'total_rows': 0,
            'unique_users': 0,
            'unique_ips': 0,
            'unique_devices': 0,
            'event_types': []
        }
    
    return {
        'total_rows': int(len(df)),
        'unique_users': int(df['user'].nunique()),
        'unique_ips': int(df['ip'].nunique()),
        'unique_devices': int(df['device'].nunique()),
        'event_types': df['event_type'].value_counts().to_dict()
    }
