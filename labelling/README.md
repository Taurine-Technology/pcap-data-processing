# Labelling PCAPs

The [label script](./label.sh) is used to label the flow files created by the [split script](../flow-splitting/split.sh).
The output of this script is a CSV file that can be cleaned by the [clean_label_csv script](./clean_label_csv.py). The
[label script](./label.sh) requires nDPI to be cloned in this directory. This can be done using the 
[install script](../install.sh).