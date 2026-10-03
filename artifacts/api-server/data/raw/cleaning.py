    #!/usr/bin/env python3
    import argparse
    from pathlib import Path
    import pandas as pd

    DEFAULT_INPUT = Path("data/raw/Cyber_Incident_Timeline_Raw_Data_1Million.csv")
    DEFAULT_OUTPUT = Path("output/incident_timeline_cleaned.csv")


    def is_date_column(column):
        name = column.lower()
        return any(word in name for word in ("date", "time", "timestamp"))


    def clean_dates(df):
        df_clean = df.copy()
        date_columns = [col for col in df_clean.columns if is_date_column(col)]

        for col in date_columns:
            df_clean[col] = pd.to_datetime(df_clean[col], errors="coerce")
            df_clean[col] = df_clean[col].fillna(pd.Timestamp("1970-01-01"))

        return df_clean


    def fill_missing(df):
        df_clean = df.copy()
        df_clean = df_clean.replace(r"^\s*$", pd.NA, regex=True)

        for col in df_clean.columns:
            if pd.api.types.is_numeric_dtype(df_clean[col]):
                df_clean[col] = df_clean[col].fillna(df_clean[col].median())
            elif pd.api.types.is_datetime64_any_dtype(df_clean[col]):
                df_clean[col] = df_clean[col].fillna(pd.Timestamp("1970-01-01"))
            else:
                df_clean[col] = df_clean[col].fillna("Unknown")

        return df_clean


    def clean_dataframe(df):
        df_clean = clean_dates(df)
        df_clean = fill_missing(df_clean)
        return df_clean


    def clean_csv(input_path, output_path):
        input_file = Path(input_path)
        output_file = Path(output_path)

        if not input_file.exists():
            raise FileNotFoundError(f"Input CSV not found: {input_file}")

        df = pd.read_csv(input_file, low_memory=False)
        cleaned_df = clean_dataframe(df)

        output_file.parent.mkdir(parents=True, exist_ok=True)
        cleaned_df.to_csv(output_file, index=False)

        return cleaned_df


    def main():
        parser = argparse.ArgumentParser(description="Clean Cyber Incident Timeline data.")
        parser.add_argument("--input", default=str(DEFAULT_INPUT))
        parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
        args = parser.parse_args()

        cleaned_df = clean_csv(args.input, args.output)

        print(f"Rows: {len(cleaned_df)}")
        print(f"Columns: {len(cleaned_df.columns)}")
        print(f"Output: {args.output}")


    if __name__ == "__main__":
        main()
