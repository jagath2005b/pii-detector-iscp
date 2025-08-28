#!/usr/bin/env python3
"""
This script processes a CSV file to detect and redact Personally Identifiable Information (PII)
based on specific rules for standalone and combinatorial PII.

Usage: python3 detector_full_candidate_name.py iscp_pii_dataset.csv
"""

import pandas as pd
import json
import re
import sys
from typing import Dict, List, Tuple, Any


class PIIDetector:
    """
    Detect & redact PII from JSON records.

    Standalone PII: phone, aadhar, passport, upi_id
    Combinatorial PII (need ≥2 together): name/full-name, email, address, device_id/ip_address
    """

    def __init__(self):
        # Standalone PII
        self.phone_pattern = re.compile(r'\b[6-9]\d{9}\b')          # Indian mobile numbers
        self.aadhar_pattern = re.compile(r'\b\d{12}\b')             # 12-digit number
        self.passport_pattern = re.compile(r'\b[A-Z]\d{7}\b')       # e.g., P1234567
        self.upi_pattern = re.compile(
            r'\b[\w\d]+@(paytm|ybl|okaxis|axisbank|hdfcbank|icici|sbi|kotak|phonepe|ibl|unionbank|canara|pnb|andhra|federal|karnataka|punjab|maharashtra|axis|indianbank|yesbank)\b'
        )
        # Other types used in combinatorial PII
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
        self.name_pattern = re.compile(r'^[A-Z][a-z]+ [A-Z][a-z]+$')  # Simple First Last
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

    def is_phone_number(self, v: str) -> bool:
        if isinstance(v, (int, float)): v = str(int(v))
        return bool(self.phone_pattern.match(str(v)))

    def is_aadhar(self, v: str) -> bool:
        if isinstance(v, (int, float)): v = str(int(v))
        return bool(self.aadhar_pattern.match(str(v)))

    def is_passport(self, v: str) -> bool:
        return bool(self.passport_pattern.match(str(v)))

    def is_upi_id(self, v: str) -> bool:
        return bool(self.upi_pattern.match(str(v)))

    def is_email(self, v: str) -> bool:
        return bool(self.email_pattern.match(str(v)))

    def is_full_name(self, v: str) -> bool:
        return bool(self.name_pattern.match(str(v)))

    def has_address_components(self, v: str) -> bool:
        s = str(v).lower()
        has_numbers = bool(re.search(r'\d+', s))        # street/house no.
        has_comma = ',' in s                            # separator
        has_pin = bool(re.search(r'\b\d{6}\b', s))      # Indian PIN
        return has_numbers and has_comma and has_pin

    # ---------- Detection ----------
    def detect_standalone_pii(self, data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        pii_found, fields = False, []
        for k, val in data.items():
            if val is None: 
                continue
            s = str(val)
            if k == 'phone' or self.is_phone_number(s):
                pii_found, fields = True, fields + [k]
            elif k == 'aadhar' or self.is_aadhar(s):
                pii_found, fields = True, fields + [k]
            elif k == 'passport' or self.is_passport(s):
                pii_found, fields = True, fields + [k]
            elif k == 'upi_id' or self.is_upi_id(s):
                pii_found, fields = True, fields + [k]
        return pii_found, fields

    def detect_combinatorial_pii(self, data: Dict[str, Any]) -> Tuple[bool, List[str], int]:
        found, fields = [], []
        has_full_name = has_email = has_address = has_device = has_name_parts = False

        for k, val in data.items():
            if val is None:
                continue
            s = str(val)
            if k == 'name' and self.is_full_name(s):
                has_full_name = True; fields.append(k)
            elif k == 'email' and self.is_email(s):
                has_email = True; fields.append(k)
            elif k == 'address' and self.has_address_components(s):
                has_address = True; fields.append(k)
            elif k in ['device_id', 'ip_address']:
                has_device = True; fields.append(k)

        if data.get('first_name') and data.get('last_name'):
            has_name_parts = True; fields.extend(['first_name', 'last_name'])

        elements = [has_full_name, has_email, has_address, has_device, has_name_parts]
        count = sum(elements)
        return count >= 2, fields, count

    # ---------- Masking ----------
    def mask_value(self, key: str, value: Any) -> str:
        if value is None:
            return None
        s = str(value)
        if isinstance(value, (int, float)) and key in ['phone', 'aadhar']:
            s = str(int(value))

        if key == 'phone' or self.is_phone_number(s):
            return s[:2] + 'X' * (len(s) - 4) + s[-2:] if len(s) >= 10 else 'X' * len(s)
        elif key == 'aadhar' or self.is_aadhar(s):
            return s[:3] + 'X' * 6 + s[-3:] if len(s) >= 12 else 'X' * len(s)
        elif key == 'passport' or self.is_passport(s):
            return s[0] + 'X' * (len(s) - 2) + s[-1] if len(s) >= 3 else 'X' * len(s)
        elif key == 'upi_id' or self.is_upi_id(s):
            parts = s.split('@')
            if len(parts) == 2:
                u, d = parts
                mu = (u[:1] + 'X' * (len(u) - 2) + u[-1:]) if len(u) > 2 else 'X' * len(u)
                return f"{mu}@{d}"
            return 'X' * len(s)
        elif key == 'email' or self.is_email(s):
            parts = s.split('@')
            if len(parts) == 2:
                u, d = parts
                mu = (u[:1] + 'X' * (len(u) - 2) + u[-1:]) if len(u) > 2 else 'X' * len(u)
                return f"{mu}@{d}"
            return 'X' * len(s)
        elif key == 'name' and self.is_full_name(s):
            return ' '.join((p[0] + 'X' * (len(p) - 1)) if len(p) > 1 else 'X' for p in s.split())
        elif key in ['first_name', 'last_name']:
            return s[0] + 'X' * (len(s) - 1) if len(s) > 1 else 'X'
        elif key == 'address':
            return '[REDACTED_ADDRESS]'
        elif key in ['device_id', 'ip_address']:
            return f"[REDACTED_{key.upper()}]"
        else:
            return '[REDACTED_PII]'

    # ---------- Per-record processing ----------
    def process_record(self, record: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        red = record.copy()
        has_standalone, stand_fields = self.detect_standalone_pii(record)
        has_combo, combo_fields, _ = self.detect_combinatorial_pii(record)
        is_pii = has_standalone or has_combo

        if is_pii:
            for f in stand_fields:
                if f in red: red[f] = self.mask_value(f, red[f])
            if has_combo:
                for f in combo_fields:
                    if f in red: red[f] = self.mask_value(f, red[f])
        return is_pii, red


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 detector_full_candidate_name.py <input_csv_file>")
        sys.exit(1)

    input_filename = sys.argv[1]

    try:
        df = pd.read_csv(input_filename)
        detector = PIIDetector()
        out = []

        print(f"Processing {len(df)} records...")

        # Accept either 'data_json' or 'Data_json'
        json_col = next((c for c in ['data_json', 'Data_json', 'Data_JSON', 'data_JSON'] if c in df.columns), None)
        if not json_col:
            raise KeyError("CSV must contain 'data_json' or 'Data_json' column.")

        for idx, row in df.iterrows():
            try:
                record_id = row['record_id']
                raw_json = row[json_col]
                data = json.loads(raw_json)

                is_pii, red_data = detector.process_record(data)
                out.append({
                    'record_id': record_id,
                    'redacted_data_json': json.dumps(red_data),
                    'is_pii': is_pii
                })
            except Exception as e:
                # Keep original JSON, mark as non-PII to avoid false positives on parse errors
                record_id = row.get('record_id', idx) if hasattr(row, 'get') else idx
                raw_json = row[json_col] if json_col in row else "{}"
                print(f"Error processing record {record_id}: {e}")
                out.append({
                    'record_id': record_id,
                    'redacted_data_json': raw_json,
                    'is_pii': False
                })

        pd.DataFrame(out).to_csv('redacted_output_candidate_full_name.csv', index=False)

        pii_count = sum(1 for r in out if r['is_pii'])
        print("Processing complete!")
        print(f"Total records processed: {len(out)}")
        print(f"PII records: {pii_count}")
        print(f"Non-PII records: {len(out) - pii_count}")
        print("Output saved to: redacted_output_candidate_full_name.csv")

    except FileNotFoundError:
        print(f"Error: File '{input_filename}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error processing file: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
