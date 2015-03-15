MAIN=main
SLIDES=slides
HANDOUT=handout
HANDOUT_NOTES=handout-notes

SRCTEX=$(wildcard *.tex)

all: $(SLIDES).pdf

full:  $(SLIDES).pdf $(HANDOUT).pdf $(HANDOUT_NOTES).pdf

$(SLIDES).pdf: $(SRCTEX)
	rubber --pdf $(SLIDES);

$(HANDOUT).pdf: $(SRCTEX)
	rubber --pdf $(HANDOUT);

$(HANDOUT_NOTES).pdf: $(SRCTEX)
	rubber --pdf $(HANDOUT_NOTES);

clean:
	rubber --pdf --clean
	@rm -f *~ *.aux *.log *.bbl *.blg *.vrb *.toc *.nav *.out *.snm

distclean: clean
	@rm -fr $(SLIDES).pdf $(HANDOUT).pdf $(HANDOUT_NOTES).pdf

help:
	@echo -e "Makefile usage :\n\
		  - make [all]\t\tbuild the slides\n\
		  - make full\t\tbuild the slides and the handouts\n\
		  - make clean\t\terase unuseful files\n\
		  - make distclean\terase all produced files\n\
		  - make help\t\tdisplay this help"
