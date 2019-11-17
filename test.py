import unittest
import cases

if __name__ == '__main__':
    loader = unittest.TestLoader()
    suite = loader.discover('cases', 'test_*.py')
    runner = unittest.TextTestRunner()
    runner.run(suite)
