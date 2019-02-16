from setuptools import setup, find_packages

setup(
        name = 'python_simple_ca',
        version = '0.0.1',
        license = 'GPL',
        description = 'Create CSR on the command line',
        install_requires = ['cryptography'],
        packages=find_packages(),
        url='https://github.com/jnhmn/python_simple_ca',
        entry_points={
            'console_scripts': [
                'genreq=python_simple_ca.genreq:console_entry',
                'issuecert=python_simple_ca.issuecert:console_entry',
            ],
        }
)
