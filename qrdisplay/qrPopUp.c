#include <gtk/gtk.h>
#include <signal.h>
#include <sys/time.h>

#if _DEBUG
#include <unistd.h>
#include <sys/types.h>

#define QRIMG_PATH "./qrCode.png"
#define SUCCESS_IMG_PATH "./success.png"
#define FAIL_IMG_PATH "./error.png"

#else
#include "../auth_daemon.h"
#define SUCCESS_IMG_PATH "./qrdisplay/success.png"
#define FAIL_IMG_PATH "./qrdisplay/error.png"

#endif


#define SCALE 486


void siguser1_handler(int signal);
void siguser2_handler(int signal);
void sigalarm_handler(int signal);
GtkWidget *layout;
GtkWidget *image;

int 
main(int argc, char *argv[])
{

	GtkWidget *window;
	GdkPixbuf *pixbuf;
	GError    *error;
	int a = 0;
	char ** av; 

#if 0 // printf sets an error var that breaks gtk :/
	pid = getpid();

	printf("PID: %d", pid);
#endif

	signal(SIGUSR1, siguser1_handler);
	signal(SIGUSR2, siguser2_handler);
	signal(SIGALRM, sigalarm_handler);


	setgid(100);
	setuid(1000);

	gtk_init (&a, &av);
	
	window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
	gtk_window_set_default_size(GTK_WINDOW (window), SCALE , SCALE);  
	gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);
	gtk_window_set_title (GTK_WINDOW (window), "See Instructions on Phone");
	
	layout = gtk_layout_new(NULL,NULL);
	gtk_container_add(GTK_CONTAINER (window),layout);
	
	gtk_widget_show  (layout);
	pixbuf = gdk_pixbuf_new_from_file_at_scale(QRIMG_PATH
		  ,SCALE,SCALE,1,&error);

	image = gtk_image_new_from_pixbuf(pixbuf); 
	gtk_layout_put(GTK_LAYOUT (layout), image, 0, 0);

	gtk_widget_show_all(window);
	gtk_main ();
	sleep(3);
	return 0;
}


void siguser1_handler(int signal)
{
	GtkWidget *new_image;
	GdkPixbuf *pixbuf;
	GError    *error = NULL;
	struct itimerval timer;

#if _DEBUG
	printf("QRfragment recieved sucess (sig %d)\n", signal);
#endif
	 /* Configure the timer to expire after 250 msec... */
	 timer.it_value.tv_sec = 0;
	 timer.it_value.tv_usec = 25000;
	 /* set single shot ie tv_sec = tv_usec = 0 */
	 timer.it_interval.tv_sec = 0;
	 timer.it_interval.tv_usec = 0;
	 /* Start a virtual timer. It counts down whenever this process is
	   executing. */
	 setitimer (ITIMER_VIRTUAL, &timer, NULL);


	if(setitimer(ITIMER_REAL, &timer, NULL) < 0)
	{
#if _DEBUG
		perror("setitimer ERROR");
#endif
		gtk_main_quit();
	}
	else
	{
		pixbuf = gdk_pixbuf_new_from_file_at_scale(SUCCESS_IMG_PATH
			  ,SCALE,SCALE,1,&error);

		new_image = gtk_image_new_from_pixbuf(pixbuf); 
		gtk_container_remove(GTK_CONTAINER (layout), image);
		gtk_layout_put(GTK_LAYOUT (layout), new_image, 0, 0);

		gtk_widget_show_all(layout);
	}
}

void siguser2_handler(int signal)
{
	GtkWidget *new_image;
	GdkPixbuf *pixbuf;
	GError    *error = NULL;
	struct itimerval timer;

#if _DEBUG
	printf("QRfragment recieved failure (sig %d)\n", signal);
#endif

	 /* Configure the timer to expire after 250 msec... */
	 timer.it_value.tv_sec = 0;
	 timer.it_value.tv_usec = 25000;
	 /* set single shot ie tv_sec = tv_usec = 0 */
	 timer.it_interval.tv_sec = 0;
	 timer.it_interval.tv_usec = 0;
	 /* Start a virtual timer. It counts down whenever this process is
	   executing. */
	 setitimer (ITIMER_VIRTUAL, &timer, NULL);


	if(setitimer(ITIMER_REAL, &timer, NULL) < 0)
	{
#if _DEBUG
		perror("setitimer ERROR");
#endif
		gtk_main_quit();
	}
	else
	{
		pixbuf = gdk_pixbuf_new_from_file_at_scale(FAIL_IMG_PATH
			  ,SCALE,SCALE,1,&error);

		new_image = gtk_image_new_from_pixbuf(pixbuf); 
		gtk_container_remove(GTK_CONTAINER (layout), image);
		gtk_layout_put(GTK_LAYOUT (layout), new_image, 0, 0);

		gtk_widget_show_all(layout);
	}
}

void sigalarm_handler(int signal)
{
#if _DEBUG
	printf("QRfragment closed on allarm (sig %d)\n", signal);
#endif
	gtk_main_quit();
}

/**
 * How to close a GtkWindow
 * Depends what you want to do:
 * gtk.main_quit() will totally kill the program
 * gtk.window.destroy() will destroy the window but keep the program running
 * gtk.window.hide() will hide the window so it can be opened again
 */
