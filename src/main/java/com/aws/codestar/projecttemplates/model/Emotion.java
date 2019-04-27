package com.aws.codestar.projecttemplates.model;

/**
 *
 * @author user
 */
public class Emotion {

	private String story;
	private String who;

	public String getStory() {
		return story;
	}

	public void setStory(String story) {
		this.story = story;
	}

	public String getWho() {
		return who;
	}

	public void setWho(String who) {
		this.who = who;
	}

	@Override
	public String toString() {
		return "story = " + story + ",\n" + "who = " + who; //To change body of generated methods, choose Tools | Templates.
	}

}
