import glob
from setuptools import setup, find_packages

with open('README.md', 'r') as fh:
    long_description = fh.read()

setup(
        name='aws_adfs_login',
        version='1.0.2',
        author='David Poirier',
        author_email='david-poirier-csn@users.noreply.github.com',
        description='Python 3.6+ library to enable ADFS auth against AWS',
        long_description=long_description,
        long_description_content_type='text/markdown',
        url='https://github.com/david-poirier-csn/aws_adfs_login',
        python_requires=">= 3.6",
        classifiers=[
            'Programming Language :: Python :: 3',
            'License :: OSI Approved :: Apache Software License',
            'Operating System :: MacOS :: MacOS X',
            'Operating System :: POSIX :: Linux'
            ],
        keywords='adfs',
        packages=find_packages('src'),
        package_dir={'': 'src'},
        py_modules=[splitext(basename(path))[0] for path in glob.glob('src/*.py')],
        include_package_data=True,
        install_requires=['beautifulsoup4','boto3','requests'],
    )

