package com.chat.app;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Stack;
import java.util.concurrent.TimeUnit;

// Program to check brackets are properly open-close
public class Test1 {

	public static void main(String[] args) {
		        int n = 3; // number of disks
		        towerOfHanoi(n, 'A', 'C', 'B');
		    }

		    public static void towerOfHanoi(int n, char fromRod, char toRod, char auxRod) {
		        if (n == 1) {
		            System.out.println("Move disk 1 from rod " + fromRod + " to rod " + toRod);
		            return;
		        }
		        towerOfHanoi(n - 1, fromRod, auxRod, toRod);
		        System.out.println("Move disk " + n + " from rod " + fromRod + " to rod " + toRod);
		        towerOfHanoi(n - 1, auxRod, toRod, fromRod);
		    }

}