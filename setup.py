from setuptools import setup

setup(
    name='checkpoint_client',
    version='0.0.1',
    license='MIT License',
    description='A python client to interact with CheckPoint R80 API.',
    long_description=open('README.md').read(),
    author='vavarachen',
    author_email='vavarachen@gmail.com',
    url='https://github.com/vavarachen/checkpoint_client',
    packages=['checkpoint_client', 'checkpoint_client.api_client'],
    install_requires=['requests >= 2.6.0, < 3.0.0', 'requests'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Operating System :: Microsoft',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS :: MacOS X',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Software Development :: User Interfaces'
    ]
)
