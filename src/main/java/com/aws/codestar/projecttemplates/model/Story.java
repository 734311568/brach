package com.aws.codestar.projecttemplates.model;

/**
 *
 * @author user
 */
public class Story {

	private String storyId;
	private String storyHref;
	private String who;
	private String content;

	public String getStoryId() {
		return storyId;
	}

	public void setStoryId(String storyId) {
		this.storyId = storyId;
	}

	public String getStoryHref() {
		return storyHref;
	}

	public void setStoryHref(String storyHref) {
		this.storyHref = storyHref;
	}

	public String getWho() {
		return who;
	}

	public void setWho(String who) {
		this.who = who;
	}

	public String getContent() {
		return content;
	}

	public void setContent(String content) {
		this.content = content;
	}

	@Override
	public String toString() {
		return "storyId = " + storyId + ",\n" + "storyHref = " + storyHref + ",\n" + "who = " + who + ",\n" + "content = " + content; // To change body of
		// generated methods,
		// choose Tools |
		// Templates.
	}

}
