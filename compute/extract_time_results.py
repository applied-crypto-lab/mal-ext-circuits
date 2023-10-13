
import sys, os

#WARNING preexisting compiled file will be deleted. Please rename\relocate any important previous result files

csv_names = []
csv_splits = []

try:
  results_dir = sys.argv[1]
except:
  printf("Argument 1 should be a directory")
  exit()

if results_dir[-1] != '/':
	results_dir += '/'

try:
  for i in range(1, 4):
    results_fname = results_dir + "time_test_results_" + str(i) + ".csv"
    assert(os.path.isfile(results_fname))
    csv_names.append(results_fname)
    csv_file = open(results_fname, "r")
    csv_lines = csv_file.readlines()
    csv_file.close()
    csv_splits.append([line.split(",") for line in csv_lines if ((',,,' not in line) and (len(line) > 2))])
except:
  print("Missing results files in directory", results_dir)
  exit()

PARAMETERS = 7
DATA_START = 8

def average(S): return sum(S) / len(S)

csv_header = ""
num_data_cols = len(csv_splits[0][0])
if num_data_cols - DATA_START == 1:
  csv_header = ",,,,,,,,test time (us)"
if num_data_cols - DATA_START == 3:
  csv_header = ",,,,,,,,test time (us),verification time (us),verification pctg"
else:
  print("Malformed csv files detected")

line_ctr = 0
out_lines = [csv_header]

while (line_ctr < len(csv_splits[0])):
  line = ""
  for i in range(PARAMETERS):
    line += csv_splits[0][line_ctr][i] + ","
  line += ","
  for j in range(DATA_START, len(csv_splits[0][line_ctr])):
    elements = []
    for i in range(3):
      elements.append(float(csv_splits[i][line_ctr][j].strip("\n")))
      elements.append(float(csv_splits[i][line_ctr + 1][j].strip("\n")))
    line += str(average(elements)) + ","
  line_ctr += 2
  out_lines.append(line)

out_file_name = results_dir + "compiled_time_test_results.csv"
out_file = open(out_file_name, 'w')
try:
  for line in out_lines:
    out_file.write(line + "\n")
except:
  out_file.close()
  os.remove(out_file_name)

out_file.close()

