# Network Attack detector
> details in report.pdf
## How to run this code
1. Download sample data from [this link](https://drive.google.com/file/d/1-e39EN_6SaQR7CuLyfmTFK1T9b0Z-ppQ/view?usp=sharing)
2. Put it under the same folder
3. Makes sure that all the python libraries are installed.
    1. numpy/pandas/sklearn
4. To train your own model, use the command in "train model"
    1. ex. python3 train.py ./Train ./my_model
5. Or you can use our pretrain model by command in "test model"
    1. ex. python3 predict.py ./Example_test ./my_model
## train model
> python train.py <folderpath> <save_model_path>
  
## test model
> python predict.py <folderpath> [<model_path>]

p.s. using Example_test, it will spend about 5 min.
