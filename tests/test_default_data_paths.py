import unittest
from pathlib import Path

from backend.database import DB_PATH
from backend.main import DEFAULT_DATASET_PATH


class DefaultDataPathTests(unittest.TestCase):
    def test_default_sample_data_paths_are_project_root_relative(self):
        self.assertTrue(DB_PATH.is_absolute(), "DB path should be absolute and rooted to the project")
        self.assertTrue(DEFAULT_DATASET_PATH.is_absolute(), "Default dataset path should be absolute")
        self.assertTrue(DEFAULT_DATASET_PATH.exists(), "Sample dataset file should exist in the project")
        self.assertTrue(DB_PATH.parent.exists(), "Processed data folder should exist")


if __name__ == "__main__":
    unittest.main()
