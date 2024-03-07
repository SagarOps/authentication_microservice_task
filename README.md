# Django Project

This README provides instructions on how to set up and run the Django project.

## Prerequisites

- Python 3.x
- pip package manager

## Installation

1. Clone the repository to your local machine:

    ```bash
    git clone <repository-url>
    ```

2. Navigate to the project directory:

    ```bash
    cd <project-directory>
    ```

3. Create a virtual environment:

    ```bash
    python3 -m venv venv
    ```

4. Activate the virtual environment:

    ```bash
    source venv/bin/activate
    ```

5. Install dependencies:

    ```bash
    pip install -r requirements.txt
    ```

## Database Setup

1. Apply database migrations:

    ```bash
    python3 manage.py makemigrations
    python3 manage.py migrate
    ```

## Running the Server

1. Start the Django development server:

    ```bash
    python3 manage.py runserver
    ```

2. Open your web browser and navigate to:

    [http://localhost:8000/swagger](http://localhost:8000/swagger)

    This will open the Swagger documentation where you can interact with the API endpoints.

## Deactivating the Virtual Environment

When you're done working with the project, you can deactivate the virtual environment:

```bash
deactivate
