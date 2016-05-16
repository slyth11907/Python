from numpy import exp, array, random, dot


class NeuralNetwork():
    def __init__(self):
        #This will seed the random number generator so we get the same numbers everytime it runs
        random.seed(1)

        #We do this to create a random weight for a 3 x 1 matrix, this is 3 inputs and 1 output(last column)
        #This will only get values between -1 and 1
        #|0 0 1| |0|
        #|1 1 1| |1|
        #|1 0 1| |1|
        #|0 1 1| |0|
        self.synaptic_weights = 2 * random.random((3, 1)) -1 # tThe 3 here provides us the amount of random values we want.
        #print(self.synaptic_weights)


    def __sigmoid(self, x):
        #This function takes in the weighted sum of all of the inputs and normalizes them between 0 and 1.
        #Equation:
        #1 / (1 + e^-x)
        # exp - the natural exponential
        # We have imported the E for exp already
        return 1 / (1 + exp(-x))

    def __sigmoid_derivative(self, x):

        #We use this to find the gradient of the sigmoid curve and it will also tell us the confidance of our weights for that specific output(x)
        # output * (1 - output)
        return x * (1-x)



    def train(self, training_set_inputs, training_set_outputs, number_of_training_iterations):

        for iteration in range(number_of_training_iterations):
                    #We now pass the training set to our neural network 1 layer single neuron network
                    output = self.think(training_set_inputs)

                    #We now need to calculate the error. This is done by taking the differance between the output and the predicted output
                    error = training_set_outputs - output

                    #The .T is for transpose making the array more suitable for using x and y.
                    #We multiply the error by the input and again by the gradient of the sigmoid curve.
                    #This means less confident weights are adjusted more(to be more accurate)
                    # This also means the inputs, which are zero, do not cause any changes.
                    adjustment = dot(training_set_inputs.T, error * self.__sigmoid_derivative(output))

                    #We now adjust the synaptic weights based on the curve and our error
                    self.synaptic_weights += adjustment
        

    def think(self, inputs):

        #We are passing the input to our neuron.
        #The dot fucntion does matrix multiplication
        #https://en.wikipedia.org/wiki/Matrix_multiplication      
        return self.__sigmoid(dot(inputs, self.synaptic_weights))
        


if __name__ == "__main__":

    #Create our neural network
    neural_network = NeuralNetwork()


    print("Generating Random Synaptic Weights: ")
    print(neural_network.synaptic_weights)

    #This generates our training sets
    
        #|0 0 1| |0|
        #|1 1 1| |1|
        #|1 0 1| |1|
        #|0 1 1| |0|
    training_inputs = array([[0, 0, 1],[1, 1, 1],[1, 0, 1], [0, 1, 1]])
    training_outputs = array([[0, 1, 1, 0]]).T
    

    #We can now train the neural network on this dataset
    #We are going to run this data 100k times
    neural_network.train(training_inputs, training_outputs, 100000)

    print("\nNew Synaptic Weights: ")
    print(neural_network.synaptic_weights)
    #output
    #Generating Random Synaptic Weights: 
    #[[-0.16595599]
    #[ 0.44064899]
    #[-0.99977125]]
    #New Synaptic Weights: 
    #[[ 9.67299303]
    #[-0.2078435 ]
    #[-4.62963669]]
    #We can see that the first part of the matrix(-0.16595599) is the first column starts out at - showing its less useful.
    #As it learns this column grows greater shows its learning the others are less meaningfull. Since in this exmaple only if there is a 1 in the first column will the answer be 1

    #Now that the classifier is trained, we can test it's accuracy
    print("\n\nTesting a new problem: [0, 0, 1] -> Answer: 0")
    print(neural_network.think(array([0, 0, 1])))

    print("\nTesting a new problem: [1, 1, 0] -> Answer: 1")
    print(neural_network.think(array([1, 1, 0])))








                    
