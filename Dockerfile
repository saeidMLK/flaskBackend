FROM python:3.9-slim


# Set the working directory in the container
WORKDIR /app

# Copy the rest of the working directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Make port 443 available to the world outside this container
EXPOSE 4001

# Define environment variable
ENV FLASK_APP=app.py

# Run app.py when the container launches
#CMD ["flask", "run", "--host=0.0.0.0", "--port=4000"]
CMD ["gunicorn", "--bind", "0.0.0.0:4001", "app:app"]
