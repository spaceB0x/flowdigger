#define CONFIG_H

#define MAXBUF 1024
#define DELIM "="

//some method declarations for config
//void set_config_defaults();
struct config set_config_from_file(const char *);
//int set_config_from_argv(const char *, char *, int);
void print_config(struct config *);

const char *config_file_path = "../flowdigger.conf";

//struct to hold config vars
struct config{
  char *collector_ip;     //ip of flow collector
  char *interface;
  unsigned short collector_port;
  u_int digger_enabled;
  char *proxy_ip;
};

struct config set_config_from_file(const char *filename){
  struct config conf;
  FILE *file = fopen(filename, "r");
  if (file != NULL){
    char line[MAXBUF];
    int i = 0;

    while(fgets(line, sizeof(line),file) != NULL){
      char *cfline;
      cfline = strstr((char *)line,DELIM);
      cfline = cfline + strlen(DELIM);
      strtok(cfline, "\n");

      if (i == 0){
        //strcpy(conf.collector_ip, cfline);
        conf.collector_ip= malloc(strlen(cfline));
        strcpy(conf.collector_ip, cfline);
        }
      else if (i == 1){
        conf.collector_port = (unsigned short)atoi(cfline);
        }
      else if (i == 2){
        //strcpy(conf.interface, cfline);
        //conf.interface = (char *)cfline;
        conf.interface= malloc(strlen(cfline));
        strcpy(conf.interface, cfline);
        }
      else if (i == 3){
        conf.digger_enabled = (u_int)atoi(cfline);
        }
      else if ((i == 4) && (cfline != NULL)){
        if(conf.digger_enabled == 1){
          conf.proxy_ip= malloc(strlen(cfline));
          strcpy(conf.proxy_ip, cfline);
          }
        else{conf.proxy_ip = NULL;}
        }

        i++;
      } //end while
      fclose(file);
    }//end if file
    return conf;
}

void print_config(struct config *conf){
  printf("Collector IP: %s\nCollectorPort: %u\nListening on interface: %s\nDigger Flag: %u\n", conf->collector_ip, conf->collector_port, conf->interface, conf->digger_enabled);
  if(conf->proxy_ip != NULL){
    printf("Proxy IP for digging is: %s\n", conf->proxy_ip);
  }
}
