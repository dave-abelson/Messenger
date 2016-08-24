#include <string.h>
#include <stdlib.h>
#include <ncurses.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/inotify.h>
#include <menu.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#define CTRLD 	4

typedef struct textLine{
	char text[1024];
	struct textLine *next;
	struct textLine *prev;
}textLine_t;

typedef struct textList{
	textLine_t *head;
	textLine_t *tail;
}textList_t;

char* reloadWindow(char* wType);
char* promptUserInput(char* pType);
int promptNewSearch();
textList_t* initTextList();
textLine_t* pushText(textList_t* tl, char* text);
int clearTextList(textList_t* tl);
void freeTextList(textList_t* tl);
void displayInotifyEvent(struct inotify_event *i);

textList_t* textFile;
char *menuOne[] = {"Sort Log", "Filter Log", "Search for Keyword", "Exit"};
char *ascDesc[] = {"Ascending Order", "Descending Order", "Exit"};
char *menuSort[] = {"Date", "Time", "Username", "Command", "IP Address", "Port", "Exit"};
int m1choices, adchoices, mschoices;
int isLeaf, selectedAD;
int col, row;
int finalOption, isSort;
int child_status;

int main(int argc, char** argv){
	if(argc != 2){
		printf("\x1B[1;31mUsage: ./logEditor <FILENAME>\x1B[0m\n");
		return EXIT_FAILURE;
	}
	FILE* fp = fopen(argv[1], "r");
	if(fp == NULL){
		printf("\x1B[1;31mLog file not found!\x1B[0m\n");
		printf("Exiting in 3...\n");
		sleep(1);
		printf("Exiting in 2...\n");
		sleep(1);
		printf("Exiting in 1...\n");
		sleep(1);
		printf("Goodbye.\n");
		return EXIT_FAILURE;
	}

	isLeaf = 0;
	selectedAD = 0;
	m1choices = ARRAY_SIZE(menuOne);
	adchoices = ARRAY_SIZE(ascDesc);
	mschoices = ARRAY_SIZE(menuSort);
	char* returned;
	char sortChoice[1024];
	memset(sortChoice, '\0', 1024);
	int run = 1, asc = 0, desc = 0, keyword = 0;
	textFile = initTextList();

	initscr();
	start_color();
	clear();
	noecho();
	cbreak();
	keypad(stdscr, TRUE);
	getmaxyx(stdscr, row, col);
	init_pair(1, COLOR_GREEN, COLOR_BLACK);

	pid_t notifypid = fork();
	if(notifypid == 0){
		int inotifyfd = inotify_init();
		inotify_add_watch(inotifyfd, argv[1], IN_ALL_EVENTS);
		ssize_t Read;
		char* p;
		struct inotify_event *event;
		char buf[1024];
		memset(buf, '\0', 1024);
		while(1){
			Read = read(inotifyfd, buf, 1024);
			for(p = buf; p < buf + Read;){
				event = (struct inotify_event *)p;
				displayInotifyEvent(event);
				p += sizeof(struct inotify_event) + event->len;
			}
		}
	}

	while(run){
		returned = reloadWindow("MenuOne");

		while(1){
			if(!strcmp(returned, "Exit")){
				mvprintw(20, 20, "Hit enter to exit.");
				getch();
				endwin();
				free(returned);
				clearTextList(textFile);
				freeTextList(textFile);
				return EXIT_SUCCESS;
			}
			else if(!strcmp(returned, "Sort Log")){
				isSort = 1;
				free(returned);
				returned = reloadWindow("AscDesc");
				if(!strcmp(returned, "Ascending Order"))
					asc = 1;
				else if(!strcmp(returned, "Descending Order"))
					desc = 1;
			}
			else if(!strcmp(returned, "Filter Log")){
				returned = promptUserInput(returned);
				keyword = 1;
				break;
			}
			else if(isLeaf){
				returned = promptUserInput(returned);
				break;
			}
			else if(selectedAD){
				free(returned);
				returned = reloadWindow("MenuSort");
				strcpy(sortChoice, returned);
				// free(returned);
				if(!strcmp(sortChoice, "IP Address") || !strcmp(sortChoice, "Port")){
					returned = promptUserInput(returned);
					keyword = 1;
				}
				break;
			}
			else if(!strcmp(returned, "Search for Keyword")){
				returned = promptUserInput(returned);
				keyword = 1;
				break;
			}
			else{
				mvprintw(20, 20, "You should never reach here dude...");
				getch();
				endwin();
				free(returned);
				clearTextList(textFile);
				freeTextList(textFile);
				return EXIT_SUCCESS;
			}
		}
		clear();
		move(0, 0);
		if(keyword){
			pid_t pid;
			if((pid = fork()) == 0){
				FILE *file = fopen("auditTemp.log", "w");
				int fileFd = fileno(file);
				dup2(fileFd, 1);
				char *greparams[4];
				greparams[0] = "grep";
				greparams[1] = returned;
				greparams[2] = argv[1];
				greparams[3] = NULL;
				execvp(greparams[0], greparams);
				fclose(file);
			}else{
				wait(&child_status);
			}
			FILE *files = fopen("auditTemp.log", "r");
			int fileFd = fileno(files);
			char buf[1];
			memset(buf, '\0', 1);
			int x, y;
			(void)x;
			attron(COLOR_PAIR(1));
			while(read(fileFd, buf, 1) == 1){
				getyx(stdscr, y, x);
				if(y == (row - 1)){
					attroff(COLOR_PAIR(1));
					printw("<- Press Any Key To Move To Next Page ->");
					attron(COLOR_PAIR(1));
					getch();
					clear();
					move(0, 0);
				}
				printw("%c", buf[0]);
				refresh();
			}
			attroff(COLOR_PAIR(1));
			printw("<- Press Any Key To Exit ->");
			getch();
			if(promptNewSearch() == 0){
				endwin();
				fclose(files);
				break;
			}
		}else if(asc || desc){
			int daChoice; /* 0 = date, 1 = time, 2 = username */
			if(!strcmp(sortChoice, "Date"))
				daChoice = 0;
			else if(!strcmp(sortChoice, "Time"))
				daChoice = 1;
			else if(!strcmp(sortChoice, "Username"))
				daChoice = 2;
			else if(!strcmp(sortChoice, "Command"))
				daChoice = 3;
			pid_t pid;
			if((pid = fork()) == 0){
				FILE *file = fopen("auditTemp.log", "w");
				int fileFd = fileno(file);
				dup2(fileFd, 1);
				if(daChoice == 0){
					char *sortparams[4];
					sortparams[0] = "sort";
					sortparams[1] = "-b";
					sortparams[2] = argv[1];
					sortparams[3] = NULL;
					execvp(sortparams[0], sortparams);
				}else if(daChoice == 1){
					char *sortparams[6];
					sortparams[0] = "sort";
					sortparams[1] = "-b";
					sortparams[2] = "-t-";
					sortparams[3] = "-k2";
					sortparams[4] = argv[1];
					sortparams[5] = NULL;
					execvp(sortparams[0], sortparams);
				}else if(daChoice == 2){
					char *sortparams[5];
					sortparams[0] = "sort";
					sortparams[1] = "-b";
					sortparams[2] = "-k2";
					sortparams[3] = argv[1];
					sortparams[4] = NULL;
					execvp(sortparams[0], sortparams);
				}else if(daChoice == 3){
					char *sortparams[5];
					sortparams[0] = "sort";
					sortparams[1] = "-b";
					sortparams[2] = "-k3";
					sortparams[3] = argv[1];
					sortparams[4] = NULL;
					execvp(sortparams[0], sortparams);
				}
			}else{
				wait(&child_status);
			}
			if(desc){
				FILE *file = fopen("auditTemp.log", "r");
				char buf[1];
				memset(buf, '\0', 1);
				int x, y;
				(void)x;
				attron(COLOR_PAIR(1));
				char temp[1024];
				memset(temp, '\0', 1024);
				while(fgets(temp, sizeof(temp), file)){
					pushText(textFile, (char*)temp);
					memset(temp, '\0', 1024);
				}
				textLine_t* cur = textFile->tail;
				while(cur != NULL){
					getyx(stdscr, y, x);
					if(y == (row - 1)){
						attroff(COLOR_PAIR(1));
						printw("<- Press Any Key To Move To Next Page ->");
						attron(COLOR_PAIR(1));
						getch();
						clear();
						move(0, 0);
					}
					printw("%s", cur->text);
					refresh();
					cur = cur->prev;
				}
				attroff(COLOR_PAIR(1));
				// clearTextList(textFile);
				printw("<- Press Any Key To Exit ->");
				getch();
				if(promptNewSearch() == 0){
					endwin();
					fclose(file);
					break;
				}
			}
			else{
				FILE *file = fopen("auditTemp.log", "r");
				int fileFd = fileno(file);
				char buf[1];
				memset(buf, '\0', 1);
				int x, y;
				(void)x;
				attron(COLOR_PAIR(1));
				while(read(fileFd, buf, 1) == 1){
					getyx(stdscr, y, x);
					if(y == (row - 2)){
						attroff(COLOR_PAIR(1));

						printw("<- Press Any Key To Move To Next Page ->");
						attron(COLOR_PAIR(1));
						getch();
						clear();
						move(0, 0);
					}
					printw("%c", buf[0]);
					refresh();
				}
				attroff(COLOR_PAIR(1));
				printw("<- Press Any Key To Exit ->");
				getch();
				if(promptNewSearch() == 0){
					endwin();
					fclose(file);
					break;
				}
			}
		}
	}
	clearTextList(textFile);
	freeTextList(textFile);
	return EXIT_SUCCESS;
}

/*
 * @param wType the type of window to be loaded.
 * @return the choice chosen.
 */
char* reloadWindow(char* wType){
	int c, esc = 0;
	ITEM ** options;
	ITEM * curChoice = NULL;
	char* curChoiceString = calloc(1, 1024);
	clear();
	init_pair(1, COLOR_GREEN, COLOR_BLACK);
	init_pair(2, COLOR_RED, COLOR_BLACK);
	int choice;

	if(!strcmp(wType, "MenuOne")){
		choice = 1;
		options = (ITEM **)calloc(m1choices+1, sizeof(ITEM *));
		for(int i = 0; i < m1choices; ++i)
			options[i] = new_item(menuOne[i], NULL);
		options[m1choices] = (ITEM *)NULL;
	}else if(!strcmp(wType, "AscDesc")){
		choice = 2;
		options = (ITEM **)calloc(adchoices+1, sizeof(ITEM *));
		for(int i = 0; i < adchoices; ++i)
			options[i] = new_item(ascDesc[i], NULL);
		options[adchoices] = (ITEM *)NULL;
		selectedAD = 1;
	}else if(!strcmp(wType, "MenuSort")){
		choice = 3;
		options = (ITEM **)calloc(mschoices+1, sizeof(ITEM *));
		for(int i = 0; i < mschoices; ++i)
			options[i] = new_item(menuSort[i], NULL);
		options[mschoices] = (ITEM *)NULL;
	}else if(!strcmp(wType, "MenuFilter")){
		choice = 4;
		options = (ITEM **)calloc(mschoices+1, sizeof(ITEM *));
		for(int i = 0; i < mschoices; ++i)
			options[i] = new_item(menuSort[i], NULL);
		options[mschoices] = (ITEM *)NULL;
		isLeaf = 1;
	}else{
		return NULL; // WINDOW TYPE DOESN'T EXIST
	}
	MENU *mainMenu = new_menu((ITEM **)options);
	attron(COLOR_PAIR(1));
	mvprintw(LINES - 5, 0, "Hit <ENTER> to select option.");
	attroff(COLOR_PAIR(1));

	menu_opts_off(mainMenu, O_ONEVALUE);
	set_menu_fore(mainMenu, COLOR_PAIR(2));

	post_menu(mainMenu);
	refresh();

	while(1){   
		c = getch();
		switch(c){	
			case KEY_DOWN:
		        menu_driver(mainMenu, REQ_DOWN_ITEM);
				break;
			case KEY_UP:
				menu_driver(mainMenu, REQ_UP_ITEM);
				break;
			case '\n':
				menu_driver(mainMenu, REQ_TOGGLE_ITEM);
				curChoice = current_item(mainMenu);
				esc = 1;
				break;
		}
		if(esc && (curChoice != NULL))
			break;
	}
	strcpy(curChoiceString, (curChoice->name.str));
	curChoice = NULL;
	if(choice == 1){
		for(int k = 0; k < m1choices; ++k)
			free_item(options[k]);
	}else if(choice == 2){
		for(int k = 0; k < adchoices; ++k)
			free_item(options[k]);
	}else if(choice == 3 || choice == 4){
		for(int k = 0; k < mschoices; ++k)
			free_item(options[k]);
	}
	free_menu(mainMenu);
	if(strcmp(curChoiceString, "Exit") && !strcmp(wType, "AscDesc")){
		selectedAD = 1;
	}
	return curChoiceString;
}

char* promptUserInput(char* pType){
	int c, rowPos = (row/2), colPos = (col/2) - (col/4) + 8;
	int x = 0;
	char imaBeast[1024];
	memset(imaBeast, '\0', 1024);
	char* uInput = calloc(1, 1024);
	clear();
	init_pair(1, COLOR_GREEN, COLOR_BLACK);
	init_pair(2, COLOR_RED, COLOR_BLACK);
	if(!strcmp(pType, "Filter Log"))
		mvprintw(rowPos, colPos, "Please enter field to filter by: ");
	else if(!strcmp(pType, "Search for Keyword"))
		mvprintw(rowPos, colPos, "Please enter keyword to search for: ");
	else
		mvprintw(rowPos, colPos, "Please enter the %s: ", pType);
	free(pType);
	echo();
	while((c = getch()) != '\n'){
		mvprintw(row, col+x, "%c", c);
		refresh();
		imaBeast[x++] = c;
	}
	noecho();
	clear();
	strcpy(uInput, imaBeast);
	mvprintw(rowPos, colPos, "You entered: %s.", uInput);
	mvprintw(rowPos+1, colPos, "Please hit enter to continue.");
	refresh();
	getch();
	clear();
	return uInput;
}

/*
 * Returns 1 if user wants another search. 0 if not.
 */
int promptNewSearch(){
	clear();
	int c;
	mvprintw(0, 0, "Would you like another search? (Y/N)");
	while(1){
		c = getch();
		switch(c){
			case 'y':
				return 1;
			case 'n':
				return 0;
			case 'Y':
				return 1;
			case 'N':
				return 0;
			default:
				break;
		}
	}
}

textList_t* initTextList(){
	textList_t* tl = (textList_t*)malloc(sizeof(textList_t));
	if(tl == NULL){
		clear();
		mvprintw(0, 0, "No space on heap to allocate!");
		endwin();
		exit(1);
	}
	tl->head = NULL;
	tl->tail = NULL;
	return tl;
}

textLine_t* pushText(textList_t* tl, char* text){
	textLine_t* new = (textLine_t*)malloc(sizeof(textLine_t));
	if(new == NULL){
		clear();
		mvprintw(0, 0, "No space on heap to allocate!");
		endwin();
		exit(1);
	}
	strcpy(new->text, text);
	if(tl->head == NULL){ //no nodes in list
		tl->head = new;
		tl->tail = new;
	}else if(tl->head != NULL){
		if(tl->head == tl->tail){ //if there is one node in list
			tl->head->next = new;
			tl->tail = new;
			new->prev = tl->head;
		}
		else if(tl->head != tl->tail){ //two or more nodes in list
			tl->tail->next = new;
			new->prev = tl->tail;
			tl->tail = new;
		}
	}
	return new;
}

int clearTextList(textList_t* tl){
	if(tl->head == NULL){
		return 0;
	}
	else{
		textLine_t *i = tl->head;
		textLine_t *temp;
		int x = 0;
		while(i != NULL){
			temp = i;
			i = i->next;
			free(temp);
			x++;
		}
		return x; 
	}
}

void freeTextList(textList_t* tl){
	free(tl);
}

void displayInotifyEvent(struct inotify_event *i){
    if (i->mask & IN_ACCESS)        
    	mvprintw(30, 10, "File was accessed (read)!");
    if (i->mask & IN_ATTRIB)        
    	mvprintw(30, 10, "Metadata was changed!");
    if (i->mask & IN_CLOSE_NOWRITE) 
    	mvprintw(30, 10, "File previously opened was closed!");
    if (i->mask & IN_CLOSE_WRITE)   
    	mvprintw(30, 10, "File opened (not for reading) was closed!");
    if (i->mask & IN_CREATE)        
    	mvprintw(30, 10, "File was created in the directory!");
    if (i->mask & IN_DELETE)        
    	mvprintw(30, 10, "File was deleted in the directory!");
    if (i->mask & IN_DELETE_SELF)   
    	mvprintw(30, 10, "File itself was deleted! :(");
    if (i->mask & IN_MODIFY)        
    	mvprintw(30, 10, "File was recently modified!");
    if (i->mask & IN_MOVE_SELF)     
    	mvprintw(30, 10, "File was moved!");
    if (i->mask & IN_MOVED_FROM)    
    	mvprintw(30, 10, "File was moved out of watched directory!");
    if (i->mask & IN_MOVED_TO)      
    	mvprintw(30, 10, "File was moved into watched directory!");
    if (i->mask & IN_OPEN)          
    	mvprintw(30, 10, "File was opened!");
}