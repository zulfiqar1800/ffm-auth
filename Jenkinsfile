pipeline {
    agent any
    
    stages {environment {
        // SonarQube credentials and project key
        SONAR_HOST_URL = 'http://107.22.52.66:9000'
        SONAR_PROJECT_KEY = 'sonar token'
        // Docker Hub credentials (if pushing to Docker Hub)
        DOCKER_HUB_CREDENTIALS_ID = 'rasheed1800'
    }
     stages {
        stage('Checkout') {
            steps {
                git branch: 'main', url: 'https://github.com/zulfiqar1800/ffm-auth.git'
            }

      }

      stage('OWASP Dependency Check') {
            steps {
                // Assuming OWASP Dependency Check is configured in Jenkins
                dependencyCheck odcInstallation: 'OWASP Dependency-Check Vulnerabilities'
            }
        }
        stage('SonarQube Analysis') {
            steps {
                withSonarQubeEnv(credentialsId: 'sonar') { // Credential ID for SonarQube token
                    sh "mvn clean install sonar:sonar -Dsonar.projectKey=${SONAR_PROJECT_KEY} -Dsonar.host.url=${SONAR_HOST_URL}"
                }
            }
        }



        stage('Build') {
            steps {
                sh'''
                    echo "Building docker image..."
                    docker build -t auth-service:v1 .
                    docker tag auth-service:v1 rasheed1800/jenkins-auth-service:v$BUILD_NUMBER
                '''
            }
        }
        stage('Trivy Scan') {
            steps {
                sh "trivy image --severity HIGH,CRITICAL your-image-name:${env.BUILD_NUMBER}"
            }
        }



        stage('Push') {
            steps {
                sh'''
                    echo "Pushing docker image to dockerhub..."
                    docker push rasheed1800/jenkins-auth-service:v$BUILD_NUMBER
                '''
            }
        }

        stage('Deploy') {
            steps {
                sh'''
                    echo "Deploying into swarm..."
                    ssh ubuntu@13.218.82.221 docker service update --image rasheed1800/jenkins-auth-service:v$BUILD_NUMBER ffm_auth
                '''
            }
        }
    }
}
