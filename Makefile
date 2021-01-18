
.PHONY: clean

AS = fasm
SRC = kfs.asm
ELF = kfs
CFG = grub.cfg
ISO = iso

TARGET = achiu-au.iso

all: $(TARGET) ; 

$(TARGET): $(SRC)
	@$(AS) $< $(ELF)
	@mkdir -p $(ISO)/boot/grub
	@cp $(ELF) $(ISO)/boot
	@cp grub.cfg $(ISO)/boot/grub
	@grub-mkrescue -o $@ $(ISO)

clean:
	@rm -rf $(ISO) $(TARGET) $(ELF)
